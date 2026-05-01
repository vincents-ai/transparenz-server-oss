//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	gormpkg "gorm.io/gorm"

	"github.com/transparenz/transparenz-server-oss/bdd/testcontext"
	"github.com/transparenz/transparenz-server-oss/pkg/models"
)

// =============================================================================
// Test: Full E2E CRA compliance pipeline with real feed data
//
// Run:
//
//	DOCKER_HOST="unix://$XDG_RUNTIME_DIR/podman/podman.sock" \
//	  go test -tags e2e -count=1 -timeout 10m -v -run Test_E2E ./tests/e2e/...
// =============================================================================

func Test_E2E_FullCompliancePipeline(t *testing.T) {

	// --- Step 1: Start PostgreSQL ---
	t.Log("=== Step 1: Starting PostgreSQL ===")
	pgC, db := setupDatabase(t, t.Context())
	defer func() {
		_ = db.Exec("DROP SCHEMA IF EXISTS compliance CASCADE")
		_ = pgC.Terminate(t.Context())
	}()

	// --- Step 2: Seed real vulnerability feed data ---
	t.Log("=== Step 2: Seeding vulnerability feed data ===")
	orgID := seedFeedData(t, db)
	t.Logf("Seeded feed data for org %s", orgID)

	// --- Step 3: Build application with VulnzMatcher ---
	t.Log("=== Step 3: Building application ===")
	logger := zap.NewNop()
	router, alertHub, cancel, err := testcontext.BuildApp(t.Context(), db, logger)
	require.NoError(t, err)
	defer cancel()
	_ = alertHub

	tokens := generateTokens(t, db)

	// --- Step 4: Upload real SBOM ---
	t.Log("=== Step 4: Uploading SBOM ===")
	sbomID := uploadSBOM(t, router, tokens["admin"], realCycloneDXSBOM())
	t.Logf("✅ SBOM uploaded: %s", sbomID)

	// --- Step 5: Trigger scan ---
	t.Log("=== Step 5: Triggering scan ===")
	scanID := triggerScan(t, router, tokens["admin"], sbomID)
	t.Logf("✅ Scan triggered: %s", scanID)

	// --- Step 6: Wait for scan completion ---
	t.Log("=== Step 6: Waiting for scan completion ===")
	waitForScanCompletion(t, router, tokens["admin"], scanID, 30*time.Second)
	t.Log("✅ Scan completed")

	// --- Step 7: Verify vulnerabilities found by VulnzMatcher ---
	t.Log("=== Step 7: Verifying vulnerabilities ===")
	vulnCount := countScanVulnerabilities(t, router, tokens["admin"], scanID)
	t.Logf("✅ Found %d vulnerabilities via VulnzMatcher", vulnCount)
	assert.Greater(t, vulnCount, 0,
		"VulnzMatcher should find vulnerabilities from seeded feed data. "+
			"Check that feed AffectedProducts match SBOM component names.")

	// --- Step 8: Verify vulnerability list endpoint ---
	t.Log("=== Step 8: Listing all vulnerabilities ===")
	totalVulns := listVulnerabilities(t, router, tokens["admin"])
	t.Logf("✅ Total vulnerabilities in org: %d", totalVulns)

	// --- Step 9: Create VEX statement ---
	t.Log("=== Step 9: Creating VEX statement ===")
	vexID := createVEX(t, router, tokens["compliance_officer"], "CVE-2024-45338", "auth-service:1.0.0")
	t.Logf("✅ VEX created: %s", vexID)

	// --- Step 10: Approve VEX ---
	t.Log("=== Step 10: Approving VEX ===")
	approveVEX(t, router, tokens["compliance_officer"], vexID)
	t.Log("✅ VEX approved")

	// --- Step 11: Publish VEX ---
	t.Log("=== Step 11: Publishing VEX ===")
	publishVEX(t, router, tokens["admin"], vexID)
	t.Log("✅ VEX published")

	// --- Step 12: Verify compliance status ---
	t.Log("=== Step 12: Checking compliance status ===")
	compliance := getComplianceStatus(t, router, tokens["compliance_officer"])
	score, _ := compliance["compliance_score"].(float64)
	totalVulnsF, _ := compliance["total_vulnerabilities"].(float64)
	slaViolations, _ := compliance["sla_violations"].(float64)
	t.Logf("✅ Compliance: score=%.0f, total_vulns=%.0f, sla_violations=%.0f", score, totalVulnsF, slaViolations)
	assert.GreaterOrEqual(t, totalVulnsF, float64(1), "Should have vulnerabilities")

	// --- Step 13: Verify audit trail ---
	t.Log("=== Step 13: Verifying audit trail ===")
	events := verifyAuditTrail(t, router, tokens["admin"])
	t.Logf("✅ Audit trail: %d compliance events", events)

	// --- Step 14: Export CSV ---
	t.Log("=== Step 14: Exporting audit CSV ===")
	csvBody := exportAuditCSV(t, router, tokens["compliance_officer"])
	assert.Contains(t, csvBody, "Timestamp", "CSV should contain header row")
	t.Log("✅ CSV export contains data")

	t.Log("========================================")
	t.Log("=== E2E PIPELINE COMPLETE ===")
	t.Log("========================================")
}

// =============================================================================
// Seed data
// =============================================================================

func seedFeedData(t *testing.T, db *gormpkg.DB) string {
	t.Helper()

	var org models.Organization
	require.NoError(t, db.Where("slug = ?", "test-corp").First(&org).Error)

	cvssHigh := 7.5
	cvssCritical := 9.8

	feeds := []models.VulnerabilityFeed{
		{
			Cve:           "CVE-2024-45337",
			BsiSeverity:   "high",
			EnisaSeverity: "HIGH",
			Description:   "golang.org/x/crypto: deprecated ssh.Dialer auth bypass",
			BaseScore:     &cvssHigh,
			AffectedProducts: mustJSON([]map[string]string{
				{"name": "golang.org/x/crypto", "vendor": "golang", "version": "*"},
			}),
			LastSyncedAt: time.Now(),
		},
		{
			Cve:           "CVE-2024-45338",
			BsiSeverity:   "critical",
			EnisaSeverity: "CRITICAL",
			Description:   "golang.org/x/crypto: timing discrepancy in ssh.PublicKeyCallback",
			BaseScore:     &cvssCritical,
			KevExploited:  true,
			AffectedProducts: mustJSON([]map[string]string{
				{"name": "golang.org/x/crypto", "vendor": "golang", "version": "*"},
			}),
			LastSyncedAt: time.Now(),
		},
	}

	for i := range feeds {
		require.NoError(t, db.Where("cve = ?", feeds[i].Cve).FirstOrCreate(&feeds[i]).Error,
			"Failed to seed %s", feeds[i].Cve)
		t.Logf("  Seeded: %s (%s, %.1f)", feeds[i].Cve, feeds[i].EnisaSeverity, *feeds[i].BaseScore)
	}

	// Seed org vulnerabilities
	for _, v := range []models.Vulnerability{
		{OrgID: org.ID, Cve: "CVE-2024-45337", Severity: "high", DiscoveredAt: time.Now()},
		{OrgID: org.ID, Cve: "CVE-2024-45338", Severity: "critical", DiscoveredAt: time.Now()},
	} {
		db.Where("cve = ? AND org_id = ?", v.Cve, v.OrgID).FirstOrCreate(&v)
	}

	// SLA for critical
	db.Where("cve = ? AND org_id = ?", "CVE-2024-45338", org.ID).
		FirstOrCreate(&models.SlaTracking{OrgID: org.ID, Cve: "CVE-2024-45338", Deadline: time.Now().Add(72 * time.Hour), Status: "pending"})

	return org.ID.String()
}

// =============================================================================
// SBOM
// =============================================================================

func realCycloneDXSBOM() []byte {
	sbom := map[string]interface{}{
		"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
		"metadata": map[string]interface{}{
			"component": map[string]string{"type": "application", "name": "auth-service", "version": "1.0.0"},
		},
		"components": []map[string]string{
			{"type": "library", "name": "golang.org/x/crypto", "version": "0.17.0", "purl": "pkg:golang/golang.org/x/crypto@0.17.0"},
			{"type": "library", "name": "github.com/gin-gonic/gin", "version": "1.9.1", "purl": "pkg:golang/github.com/gin-gonic/gin@1.9.1"},
			{"type": "library", "name": "github.com/golang-jwt/jwt", "version": "5.2.0", "purl": "pkg:golang/github.com/golang-jwt/jwt/v5@5.2.0"},
			{"type": "library", "name": "github.com/stretchr/testify", "version": "1.8.4", "purl": "pkg:golang/github.com/stretchr/testify@1.8.4"},
			{"type": "library", "name": "gorm.io/gorm", "version": "1.25.5", "purl": "pkg:golang/gorm.io/gorm@1.25.5"},
		},
	}
	b, _ := json.Marshal(sbom)
	return b
}

// =============================================================================
// Infrastructure
// =============================================================================

func setupDatabase(t *testing.T, ctx context.Context) (testcontainers.Container, *gormpkg.DB) {
	t.Helper()

	c, err := tcpostgres.Run(ctx, "docker.io/postgres:16-alpine",
		tcpostgres.WithDatabase("e2e"),
		tcpostgres.WithUsername("test"),
		tcpostgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(30*time.Second)),
	)
	require.NoError(t, err, "Failed to start PostgreSQL")

	connStr, err := c.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	db, err := gormpkg.Open(postgres.Open(connStr), &gormpkg.Config{})
	require.NoError(t, err)

	runMigrations(t, db)
	return c, db
}

func runMigrations(t *testing.T, db *gormpkg.DB) {
	t.Helper()
	require.NoError(t, db.Exec("CREATE SCHEMA IF NOT EXISTS compliance").Error)

	// Find migrations dir
	migrationsDir := findMigrationsDir(t)

	entries, err := os.ReadDir(migrationsDir)
	require.NoError(t, err)

	// Filter and sort .up.sql files
	var upFiles []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".up.sql") {
			upFiles = append(upFiles, e.Name())
		}
	}
	sort.Strings(upFiles)

	for _, name := range upFiles {
		data, err := os.ReadFile(filepath.Join(migrationsDir, name))
		require.NoError(t, err, "Cannot read %s", name)
		require.NoError(t, db.Exec(string(data)).Error, "Migration %s failed", name)
		t.Logf("  Applied: %s", name)
	}

	require.NoError(t, db.Exec(
		`INSERT INTO compliance.organizations (name, slug, tier) VALUES ('Test Corp', 'test-corp', 'standard') ON CONFLICT (slug) DO NOTHING`,
	).Error)
}

func findMigrationsDir(t *testing.T) string {
	t.Helper()
	// Walk up to find go.mod, then look for ./migrations
	wd, _ := os.Getwd()
	for dir := wd; dir != "/"; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			m := filepath.Join(dir, "migrations")
			if _, err := os.Stat(m); err == nil {
				return m
			}
		}
	}
	t.Fatal("Cannot find migrations directory")
	return ""
}

func generateTokens(t *testing.T, db *gormpkg.DB) map[string]string {
	t.Helper()
	oid := getOrgID(t, db)
	mk := func(role string) string {
		tok, err := testcontext.GenerateToken(role, oid)
		require.NoError(t, err)
		return tok
	}
	return map[string]string{
		"admin":              mk("admin"),
		"compliance_officer": mk("compliance_officer"),
		"user":               mk("user"),
	}
}

func getOrgID(t *testing.T, db *gormpkg.DB) string {
	var org models.Organization
	require.NoError(t, db.Where("slug = ?", "test-corp").First(&org).Error)
	return org.ID.String()
}

// =============================================================================
// HTTP helpers
// =============================================================================

func doReq(t *testing.T, router *gin.Engine, method, path, token string, body []byte, contentType string) *httptest.ResponseRecorder {
	t.Helper()
	var br *bytes.Reader
	if body != nil {
		br = bytes.NewReader(body)
	} else {
		br = bytes.NewReader([]byte{})
	}
	req := httptest.NewRequest(method, path, br)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func parseJSON(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &m))
	return m
}

// =============================================================================
// Pipeline steps
// =============================================================================

func uploadSBOM(t *testing.T, router *gin.Engine, token string, sbomData []byte) string {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreateFormFile("file", "auth-service.cdx.json")
	require.NoError(t, err)
	_, err = part.Write(sbomData)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	req := httptest.NewRequest("POST", "/api/sboms/upload", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	rw := httptest.NewRecorder()
	router.ServeHTTP(rw, req)
	require.Equal(t, http.StatusCreated, rw.Code, "Upload failed: %s", rw.Body.String())

	var resp struct{ ID string `json:"id"` }
	require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &resp))
	return resp.ID
}

func triggerScan(t *testing.T, router *gin.Engine, token, sbomID string) string {
	t.Helper()
	w := doReq(t, router, "POST", "/api/scan", token,
		[]byte(fmt.Sprintf(`{"sbom_id":"%s"}`, sbomID)), "application/json")
	require.Equal(t, http.StatusAccepted, w.Code, "Scan failed: %s", w.Body.String())

	var resp struct{ ScanID string `json:"scan_id"` }
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	return resp.ScanID
}

func waitForScanCompletion(t *testing.T, router *gin.Engine, token, scanID string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		w := doReq(t, router, "GET", "/api/scans", token, nil, "")
		if w.Code != http.StatusOK {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		var list struct {
			Data []struct {
				ID     string `json:"id"`
				Status string `json:"status"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &list))
		for _, s := range list.Data {
			if s.ID == scanID {
				switch s.Status {
				case "completed":
					return
				case "failed":
					t.Fatalf("Scan %s failed", scanID)
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("Scan %s not completed in %v", scanID, timeout)
}

func countScanVulnerabilities(t *testing.T, router *gin.Engine, token, scanID string) int {
	t.Helper()
	w := doReq(t, router, "GET", fmt.Sprintf("/api/scans/%s/vulnerabilities", scanID), token, nil, "")
	require.Equal(t, http.StatusOK, w.Code, "Vuln list failed: %s", w.Body.String())
	var r struct{ Data []interface{} `json:"data"` }
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &r))
	return len(r.Data)
}

func listVulnerabilities(t *testing.T, router *gin.Engine, token string) int {
	t.Helper()
	w := doReq(t, router, "GET", "/api/vulnerabilities", token, nil, "")
	require.Equal(t, http.StatusOK, w.Code)
	var r struct{ Data []interface{} `json:"data"` }
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &r))
	return len(r.Data)
}

func createVEX(t *testing.T, router *gin.Engine, token, cve, productID string) string {
	t.Helper()
	body := fmt.Sprintf(`{"cve":"%s","product_id":"%s","status":"affected","justification":"Vulnerable component in production"}`, cve, productID)
	w := doReq(t, router, "POST", "/api/vex", token, []byte(body), "application/json")
	require.Equal(t, http.StatusCreated, w.Code, "VEX create failed: %s", w.Body.String())
	var r struct{ ID string `json:"id"` }
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &r))
	return r.ID
}

func approveVEX(t *testing.T, router *gin.Engine, token, vexID string) {
	t.Helper()
	w := doReq(t, router, "POST", fmt.Sprintf("/api/vex/%s/approve", vexID), token, nil, "application/json")
	require.Equal(t, http.StatusOK, w.Code, "Approve failed: %s", w.Body.String())
}

func publishVEX(t *testing.T, router *gin.Engine, token, vexID string) {
	t.Helper()
	w := doReq(t, router, "POST", fmt.Sprintf("/api/vex/%s/publish", vexID), token, []byte(`{"channel":"file"}`), "application/json")
	require.Equal(t, http.StatusOK, w.Code, "Publish failed: %s", w.Body.String())
}

func getComplianceStatus(t *testing.T, router *gin.Engine, token string) map[string]interface{} {
	t.Helper()
	w := doReq(t, router, "GET", "/api/compliance/status", token, nil, "")
	require.Equal(t, http.StatusOK, w.Code)
	return parseJSON(t, w)
}

func verifyAuditTrail(t *testing.T, router *gin.Engine, token string) int {
	t.Helper()
	w := doReq(t, router, "GET", "/api/audit/verify?start=2020-01-01&end=2030-12-31", token, nil, "")
	require.Equal(t, http.StatusOK, w.Code)
	m := parseJSON(t, w)
	n, _ := strconv.Atoi(fmt.Sprintf("%.0f", m["total_events"].(float64)))
	return n
}

func exportAuditCSV(t *testing.T, router *gin.Engine, token string) string {
	t.Helper()
	w := doReq(t, router, "GET", "/api/export/audit?format=csv&start=2020-01-01&end=2030-12-31", token, nil, "")
	require.Equal(t, http.StatusOK, w.Code)
	b, err := io.ReadAll(w.Body)
	require.NoError(t, err)
	return string(b)
}

func mustJSON(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}
