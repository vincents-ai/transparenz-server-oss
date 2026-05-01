//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/transparenz/transparenz-server-oss/pkg/models"
)

// =============================================================================
// SBOM Generation
// =============================================================================

type cycloneDXSBOM struct {
	BomFormat   string `json:"bomFormat"`
	SpecVersion string `json:"specVersion"`
	Version     int    `json:"version"`
	Metadata    struct {
		Component struct {
			Type    string `json:"type"`
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"component"`
	} `json:"metadata"`
	Components []struct {
		Type    string `json:"type"`
		Name    string `json:"name"`
		Version string `json:"version"`
		Purl    string `json:"purl,omitempty"`
	} `json:"components"`
}

// generateRealSBOM creates a CycloneDX SBOM representing the auth-service
// with real Go dependencies including known-vulnerable versions.
func generateRealSBOM(t *testing.T) cycloneDXSBOM {
	t.Helper()
	return cycloneDXSBOM{
		BomFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     1,
		Metadata: struct {
			Component struct {
				Type    string `json:"type"`
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"component"`
		}{
			Component: struct {
				Type    string `json:"type"`
				Name    string `json:"name"`
				Version string `json:"version"`
			}{
				Type:    "application",
				Name:    "auth-service",
				Version: "1.0.0",
			},
		},
		Components: []struct {
			Type    string `json:"type"`
			Name    string `json:"name"`
			Version string `json:"version"`
			Purl    string `json:"purl,omitempty"`
		}{
			{"library", "golang.org/x/crypto", "0.17.0", "pkg:golang/golang.org/x/crypto@0.17.0"},
			{"library", "github.com/gin-gonic/gin", "1.9.1", "pkg:golang/github.com/gin-gonic/gin@1.9.1"},
			{"library", "github.com/golang-jwt/jwt", "5.2.0", "pkg:golang/github.com/golang-jwt/jwt/v5@5.2.0"},
			{"library", "github.com/stretchr/testify", "1.8.4", "pkg:golang/github.com/stretchr/testify@1.8.4"},
			{"library", "gorm.io/gorm", "1.25.5", "pkg:golang/gorm.io/gorm@1.25.5"},
		},
	}
}

// =============================================================================
// HTTP Helpers
// =============================================================================

func doRequest(t *testing.T, router *gin.Engine, method, path, token string, body []byte) *http.Response {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w.Result()
}

// =============================================================================
// Pipeline Steps
// =============================================================================

func uploadSBOM(t *testing.T, router *gin.Engine, tokens map[string]string, sbom cycloneDXSBOM) string {
	t.Helper()

	sbomBytes, err := json.Marshal(sbom)
	require.NoError(t, err)

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, err := writer.CreateFormFile("file", "auth-service.cdx.json")
	require.NoError(t, err)
	_, err = part.Write(sbomBytes)
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	req := httptest.NewRequest("POST", "/api/sboms/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+tokens["admin"])

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code, "SBOM upload failed: %s", w.Body.String())

	var resp struct{ ID string `json:"id"` }
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	return resp.ID
}

func triggerScan(t *testing.T, router *gin.Engine, tokens map[string]string, sbomID string) string {
	t.Helper()

	body := fmt.Sprintf(`{"sbom_id":"%s"}`, sbomID)
	resp := doRequest(t, router, "POST", "/api/scan", tokens["admin"], []byte(body))
	require.Equal(t, http.StatusAccepted, resp.StatusCode, "Scan trigger failed")

	var result struct {
		ScanID string `json:"scan_id"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	return result.ScanID
}

func waitForScanCompletion(t *testing.T, router *gin.Engine, tokens map[string]string, scanID string) {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		resp := doRequest(t, router, "GET", "/api/scans", tokens["admin"], nil)
		if resp.StatusCode == http.StatusOK {
			var result struct {
				Data []struct {
					ID     string `json:"id"`
					Status string `json:"status"`
				} `json:"data"`
			}
			json.NewDecoder(resp.Body).Decode(&result)
			for _, s := range result.Data {
				if s.ID == scanID && (s.Status == "completed" || s.Status == "failed") {
					return
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal("Scan did not complete within 30s")
}

func verifyVulnerabilities(t *testing.T, router *gin.Engine, tokens map[string]string, scanID string) int {
	t.Helper()

	path := fmt.Sprintf("/api/scans/%s/vulnerabilities", scanID)
	resp := doRequest(t, router, "GET", path, tokens["admin"], nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var result struct {
		Data []interface{} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	return len(result.Data)
}

func createVEX(t *testing.T, router *gin.Engine, tokens map[string]string, cve string) string {
	t.Helper()

	body := fmt.Sprintf(`{
		"cve": "%s",
		"product_id": "auth-service:1.0.0",
		"status": "affected",
		"justification": "Vulnerable component identified in production dependency"
	}`, cve)

	resp := doRequest(t, router, "POST", "/api/vex", tokens["compliance_officer"], []byte(body))
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var result struct{ ID string `json:"id"` }
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	return result.ID
}

func approveVEX(t *testing.T, router *gin.Engine, tokens map[string]string, vexID string) {
	t.Helper()

	path := fmt.Sprintf("/api/vex/%s/approve", vexID)
	resp := doRequest(t, router, "PUT", path, tokens["compliance_officer"], nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func publishVEX(t *testing.T, router *gin.Engine, tokens map[string]string, vexID string) {
	t.Helper()

	path := fmt.Sprintf("/api/vex/%s/publish", vexID)
	body := `{"channel":"file"}`
	resp := doRequest(t, router, "PUT", path, tokens["admin"], []byte(body))
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func getComplianceStatus(t *testing.T, router *gin.Engine, tokens map[string]string) map[string]interface{} {
	t.Helper()

	resp := doRequest(t, router, "GET", "/api/compliance/status", tokens["compliance_officer"], nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	return result
}

func verifyAuditTrail(t *testing.T, router *gin.Engine, tokens map[string]string) int {
	t.Helper()

	resp := doRequest(t, router, "GET", "/api/audit/verify?start=2020-01-01&end=2030-12-31", tokens["admin"], nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var result struct {
		TotalEvents int `json:"total_events"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	return result.TotalEvents
}

func exportAuditCSV(t *testing.T, router *gin.Engine, tokens map[string]string) string {
	t.Helper()

	resp := doRequest(t, router, "GET", "/api/export/audit?format=csv&start=2020-01-01&end=2030-12-31", tokens["compliance_officer"], nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(body)
}

// =============================================================================
// SQL Table Definitions (matching migrations)
// =============================================================================

func vulnerabilityFeedsTable() string {
	return `CREATE TABLE IF NOT EXISTS compliance.vulnerability_feeds (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		cve TEXT NOT NULL UNIQUE,
		kev_exploited BOOLEAN DEFAULT false,
		kev_date_added TIMESTAMPTZ,
		enisa_euvd_id TEXT DEFAULT '',
		enisa_severity TEXT DEFAULT '',
		bsi_advisory_id TEXT DEFAULT '',
		bsi_tr_03116_compliant BOOLEAN,
		affected_products JSONB DEFAULT '[]',
		description TEXT DEFAULT '',
		base_score DECIMAL(5,4),
		base_score_vector TEXT DEFAULT '',
		epss_score DECIMAL(5,4),
		exploited_since TIMESTAMPTZ,
		bsi_severity TEXT DEFAULT '',
		kev_sources TEXT[] DEFAULT '{}',
		last_synced_at TIMESTAMPTZ DEFAULT NOW(),
		created_at TIMESTAMPTZ DEFAULT NOW(),
		updated_at TIMESTAMPTZ DEFAULT NOW()
	)`
}

func vulnerabilitiesTable() string {
	return `CREATE TABLE IF NOT EXISTS compliance.vulnerabilities (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		org_id UUID NOT NULL REFERENCES compliance.organizations(id) ON DELETE CASCADE,
		cve TEXT NOT NULL,
		cvss_score DECIMAL(3,1),
		severity TEXT,
		exploited_in_wild BOOLEAN DEFAULT false,
		kev_date_added TIMESTAMPTZ,
		euvd_id TEXT DEFAULT '',
		bsi_tr_03116_compliant BOOLEAN,
		sovereign_feed_source TEXT DEFAULT '',
		discovered_at TIMESTAMPTZ DEFAULT NOW(),
		created_at TIMESTAMPTZ DEFAULT NOW(),
		updated_at TIMESTAMPTZ DEFAULT NOW(),
		UNIQUE(org_id, cve)
	)`
}

func slaTrackingTable() string {
	return `CREATE TABLE IF NOT EXISTS compliance.sla_tracking (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		org_id UUID NOT NULL REFERENCES compliance.organizations(id) ON DELETE CASCADE,
		cve TEXT NOT NULL,
		deadline TIMESTAMPTZ NOT NULL,
		status TEXT NOT NULL DEFAULT 'pending',
		hours_remaining DECIMAL(10,2),
		created_at TIMESTAMPTZ DEFAULT NOW(),
		updated_at TIMESTAMPTZ DEFAULT NOW()
	)`
}

func sbomUploadsTable() string {
	return `CREATE TABLE IF NOT EXISTS compliance.sbom_uploads (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		org_id UUID NOT NULL REFERENCES compliance.organizations(id) ON DELETE CASCADE,
		filename TEXT NOT NULL,
		sha256 TEXT NOT NULL,
		format TEXT NOT NULL,
		data JSONB NOT NULL,
		size BIGINT NOT NULL DEFAULT 0,
		created_at TIMESTAMPTZ DEFAULT NOW(),
		updated_at TIMESTAMPTZ DEFAULT NOW()
	)`
}

func scansTable() string {
	return `CREATE TABLE IF NOT EXISTS compliance.scans (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		org_id UUID NOT NULL REFERENCES compliance.organizations(id) ON DELETE CASCADE,
		sbom_id UUID NOT NULL REFERENCES compliance.sbom_uploads(id) ON DELETE CASCADE,
		status TEXT NOT NULL DEFAULT 'pending',
		scanner_version TEXT DEFAULT '',
		started_at TIMESTAMPTZ,
		completed_at TIMESTAMPTZ,
		error_message TEXT DEFAULT '',
		created_at TIMESTAMPTZ DEFAULT NOW(),
		updated_at TIMESTAMPTZ DEFAULT NOW()
	)`
}

func scanVulnerabilitiesTable() string {
	return `CREATE TABLE IF NOT EXISTS compliance.scan_vulnerabilities (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		org_id UUID NOT NULL REFERENCES compliance.organizations(id) ON DELETE CASCADE,
		scan_id UUID NOT NULL REFERENCES compliance.scans(id) ON DELETE CASCADE,
		cve TEXT NOT NULL,
		severity TEXT NOT NULL,
		cvss_score DECIMAL(3,1),
		package_name TEXT DEFAULT '',
		package_version TEXT DEFAULT '',
		package_type TEXT DEFAULT '',
		fixed_version TEXT DEFAULT '',
		vulnerability_url TEXT DEFAULT '',
		exploited_in_wild BOOLEAN DEFAULT false,
		euvd_id TEXT DEFAULT '',
		bsi_advisory_id TEXT DEFAULT '',
		source TEXT DEFAULT '',
		p_url TEXT DEFAULT '',
		created_at TIMESTAMPTZ DEFAULT NOW()
	)`
}

func vexStatementsTable() string {
	return `CREATE TABLE IF NOT EXISTS compliance.vex_statements (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		org_id UUID NOT NULL REFERENCES compliance.organizations(id) ON DELETE CASCADE,
		cve TEXT NOT NULL,
		product_id TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'draft',
		justification TEXT DEFAULT '',
		channel TEXT DEFAULT '',
		created_by TEXT DEFAULT '',
		approved_by TEXT DEFAULT '',
		approved_at TIMESTAMPTZ,
		published_at TIMESTAMPTZ,
		created_at TIMESTAMPTZ DEFAULT NOW(),
		updated_at TIMESTAMPTZ DEFAULT NOW()
	)`
}

func vexPublicationsTable() string {
	return `CREATE TABLE IF NOT EXISTS compliance.vex_publications (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		org_id UUID NOT NULL REFERENCES compliance.organizations(id) ON DELETE CASCADE,
		vex_statement_id UUID NOT NULL REFERENCES compliance.vex_statements(id),
		channel TEXT NOT NULL,
		document JSONB,
		published_at TIMESTAMPTZ DEFAULT NOW(),
		created_at TIMESTAMPTZ DEFAULT NOW()
	)`
}

func complianceEventsTable() string {
	return `CREATE TABLE IF NOT EXISTS compliance.compliance_events (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		org_id UUID NOT NULL REFERENCES compliance.organizations(id) ON DELETE CASCADE,
		event_type TEXT NOT NULL CHECK (event_type IN ('exploited_reported', 'sla_breach', 'enisa_submission', 'notification_sent')),
		severity TEXT NOT NULL,
		cve TEXT DEFAULT '',
		reported_to_authority TEXT DEFAULT '',
		timestamp TIMESTAMPTZ DEFAULT NOW(),
		metadata JSONB DEFAULT '{}',
		signature TEXT DEFAULT '',
		signing_key_id UUID,
		previous_event_hash TEXT DEFAULT '',
		event_hash TEXT DEFAULT '',
		created_at TIMESTAMPTZ DEFAULT NOW()
	)`
}

func enisaSubmissionsTable() string {
	return `CREATE TABLE IF NOT EXISTS compliance.enisa_submissions (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		org_id UUID NOT NULL REFERENCES compliance.organizations(id) ON DELETE CASCADE,
		submission_id TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'submitted',
		csaf_document JSONB DEFAULT '{}',
		created_at TIMESTAMPTZ DEFAULT NOW(),
		updated_at TIMESTAMPTZ DEFAULT NOW()
	)`
}

func organizationsTable() string {
	return `` // already created in runE2EMigrations
}

func disclosuresTable() string {
	return `CREATE TABLE IF NOT EXISTS compliance.vulnerability_disclosures (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		org_id UUID NOT NULL REFERENCES compliance.organizations(id) ON DELETE CASCADE,
		cve TEXT NOT NULL,
		title TEXT NOT NULL,
		description TEXT DEFAULT '',
		severity TEXT DEFAULT '',
		status TEXT NOT NULL DEFAULT 'received',
		coordinator_name TEXT DEFAULT '',
		coordinator_email TEXT DEFAULT '',
		reporter_name TEXT DEFAULT '',
		reporter_email TEXT DEFAULT '',
		internal_notes TEXT DEFAULT '',
		fix_version TEXT DEFAULT '',
		due_date TIMESTAMPTZ,
		created_at TIMESTAMPTZ DEFAULT NOW(),
		updated_at TIMESTAMPTZ DEFAULT NOW()
	)`
}

func grcMappingsTable() string {
	return `CREATE TABLE IF NOT EXISTS compliance.grc_mappings (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		org_id UUID NOT NULL REFERENCES compliance.organizations(id) ON DELETE CASCADE,
		framework TEXT NOT NULL,
		control_id TEXT NOT NULL,
		mapping_type TEXT NOT NULL,
		confidence DECIMAL(5,4) DEFAULT 0,
		evidence TEXT DEFAULT '',
		created_at TIMESTAMPTZ DEFAULT NOW()
	)`
}

func alertSubscriptionsTable() string {
	return `CREATE TABLE IF NOT EXISTS compliance.alert_subscriptions (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		org_id UUID NOT NULL REFERENCES compliance.organizations(id) ON DELETE CASCADE,
		user_id TEXT NOT NULL,
		event_types TEXT[] DEFAULT '{}',
		created_at TIMESTAMPTZ DEFAULT NOW()
	)`
}

// =============================================================================
// Utility
// =============================================================================

func ptrFloat(f float64) *float64 { return &f }

func mustJSON(v interface{}) datatypes.JSON {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return datatypes.JSON(b)
}
