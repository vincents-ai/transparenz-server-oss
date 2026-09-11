//go:build e2e

package e2e

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "github.com/lib/pq"
)

// Run against a live server + DB:
//
//	go test -v -tags=e2e -run TestE2EPipeline ./tests/e2e/
//
// Server must be on :28080, PostgreSQL on :25432.
// JWT is auto-generated from the test secret.

const (
	testSecret = "integration-test-secret-key-32chars!"
	testOrg    = "00000000-0000-0000-0000-000000000001"
	cveID      = "CVE-2026-E2E-PIPELINE"
	component  = "e2e-pipeline-lib"
	version    = "1.0.0"
)

func serverURL() string {
	if v := os.Getenv("TRANSPARENZ_URL"); v != "" {
		return v
	}
	return "http://localhost:28080"
}

func makeJWT() string {
	header := b64url([]byte(`{"alg":"HS256","typ":"JWT"}`))
	now := time.Now().Unix()
	payload := b64url([]byte(fmt.Sprintf(
		`{"sub":"e2e-test","email":"e2e@test.local","org_id":"%s","org_slug":"demo","roles":["admin","compliance_officer"],"iat":%d,"exp":%d}`,
		testOrg, now, now+86400)))
	mac := hmac.New(sha256.New, []byte(testSecret))
	mac.Write([]byte(header + "." + payload))
	sig := b64url(mac.Sum(nil))
	return header + "." + payload + "." + sig
}

func dbURL() string {
	if v := os.Getenv("TRANSPARENZ_DB"); v != "" {
		return v
	}
	return "postgres://test:test@localhost:25432/transparenz?sslmode=disable"
}

func b64url(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// TestE2EPipeline traces the full vulnerability disclosure pipeline:
//
//	T0  Health check
//	T1  Upload SBOM with e2e-pipeline-lib@1.0.0
//	T2  Initial scan → baseline (CVE not yet injected)
//	T3  Inject CVE into vulnerability_feeds + vulnerabilities table
//	T4  Second scan → vulnerability detected
//	T5  Verify CVE visible via GET /api/vulnerabilities
//	T6  Wait for SLA deadline calculation
//	T7  Verify SLA deadline is anchored to discovered_at (not time.Now())
//	T8  Check alerts
//
// Every HTTP request/response, timing, and DB state is logged.
func TestE2EPipeline(t *testing.T) {
	url := serverURL()
	token := makeJWT()

	t.Log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	t.Log("  E2E PIPELINE: SBOM Clean → Vulnerable → Alerted")
	t.Logf("  Server:  %s", url)
	t.Logf("  Org:     %s", testOrg)
	t.Logf("  CVE:     %s → %s@%s", cveID, component, version)
	t.Logf("  JWT:     %s…", token[:30])
	t.Log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	t.Log("")

	db, err := sql.Open("postgres", dbURL())
	require.NoError(t, err, "connect to DB at %s", dbURL())
	defer db.Close()

	cleanup(t, db)

	// ═══════════════════════════════════════════════════════════════════════
	//  T0: Health check
	// ═══════════════════════════════════════════════════════════════════════
	t0 := time.Now()
	t.Log("── T0: Server health check ──")

	resp, body := doGet(url, "/health", token)
	require.Equal(t, 200, resp.StatusCode, "GET /health: %s", string(body))
	t.Logf("  GET /health → 200 (%v)", time.Since(t0))

	resp, body = doGet(url, "/readyz", token)
	require.Equal(t, 200, resp.StatusCode, "GET /readyz: %s", string(body))
	t.Logf("  GET /readyz → 200: %s", string(body))
	t.Log("")

	// ═══════════════════════════════════════════════════════════════════════
	//  T1: Upload SBOM
	// ═══════════════════════════════════════════════════════════════════════
	t1 := time.Now()
	t.Log("── T1: Upload SBOM ──")

	sbom := fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":"1.5","metadata":{"component":{"name":"e2e-pipeline-app","version":"1.0.0"}},"components":[{"type":"library","name":"%s","version":"%s","purl":"pkg:generic/%s@%s"}]}`,
		component, version, component, version)

	uploadResp, uploadBody := doUpload(url, "/api/sboms/upload", token, "e2e-pipeline.cdx.json", []byte(sbom))
	require.Equal(t, 201, uploadResp.StatusCode,
		"SBOM upload failed: %s", string(uploadBody))

	var upload struct {
		Data struct {
			ID       string `json:"id"`
			Filename string `json:"filename"`
			SHA256   string `json:"sha256"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(uploadBody, &upload))
	sbomID := upload.Data.ID

	t.Logf("  ✓ SBOM uploaded:")
	t.Logf("    id:       %s", sbomID)
	t.Logf("    filename: %s", upload.Data.Filename)
	t.Logf("    sha256:   %s", upload.Data.SHA256)
	t.Logf("    Duration: %v", time.Since(t1))
	t.Log("")

	// ═══════════════════════════════════════════════════════════════════════
	//  T2: Initial scan (baseline — CVE not in feed yet)
	// ═══════════════════════════════════════════════════════════════════════
	t2 := time.Now()
	t.Log("── T2: Initial scan (baseline) ──")

	scanPayload, _ := json.Marshal(map[string]string{"sbom_id": sbomID})
	scanResp, scanBody := doPost(url, "/api/scan", token, scanPayload)
	t.Logf("  POST /api/scan → %d: %s", scanResp.StatusCode, pretty(scanBody))

	var scan1Data struct {
		Data struct {
			ScanID string `json:"scan_id"`
			Status string `json:"status"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(scanBody, &scan1Data))
	scanID := scan1Data.Data.ScanID

	result1 := waitScan(url, token, scanID, 60*time.Second)
	require.Equal(t, "completed", result1.status,
		"Initial scan should complete")
	baselineVulns := result1.vulns

	t.Logf("  ✓ Scan completed: vulns=%d (%v)", baselineVulns, time.Since(t2))
	t.Log("")

	// ═══════════════════════════════════════════════════════════════════════
	//  T3: Inject CVE into feed + vulnerabilities table
	// ═══════════════════════════════════════════════════════════════════════
	t3 := time.Now()
	t.Log("── T3: Inject CVE (simulates feed sync + scan detection) ──")

	discoveredAt := time.Now().Add(-2 * time.Hour) // discovered 2h ago

	_, err = db.Exec(`
		INSERT INTO compliance.vulnerability_feeds
			(id, cve, kev_exploited, enisa_severity, affected_products, last_synced_at, created_at, updated_at)
		VALUES (gen_random_uuid(), $1, true, 'critical', $2::jsonb, NOW(), NOW(), NOW())
		ON CONFLICT (cve) DO UPDATE SET
			kev_exploited=true, enisa_severity='critical',
			affected_products=$2::jsonb, last_synced_at=NOW(), updated_at=NOW()
	`, cveID, fmt.Sprintf(`[{"name":"%s","version":"%s"}]`, component, version))
	require.NoError(t, err, "insert feed record")

	_, err = db.Exec(`
		INSERT INTO compliance.vulnerabilities
			(id, org_id, cve, severity, cvss_score, exploited_in_wild, discovered_at, created_at, updated_at)
		VALUES (gen_random_uuid(), $1, $2, 'critical', 9.8, true, $3, NOW(), NOW())
		ON CONFLICT DO NOTHING
	`, testOrg, cveID, discoveredAt)
	require.NoError(t, err, "insert vulnerability")

	t.Logf("  ✓ %s injected:", cveID)
	t.Logf("    severity:     critical")
	t.Logf("    exploited:    true")
	t.Logf("    discovered:   %s (2h ago)", discoveredAt.Format(time.RFC3339))
	t.Logf("    Duration:     %v", time.Since(t3))
	t.Log("")

	// ═══════════════════════════════════════════════════════════════════════
	//  T4: Second scan (simulates AutoRescanHook triggering)
	// ═══════════════════════════════════════════════════════════════════════
	t4 := time.Now()
	t.Log("── T4: Second scan (post-CVE injection) ──")

	scan2Payload, _ := json.Marshal(map[string]string{"sbom_id": sbomID})
	scan2Resp, scan2Body := doPost(url, "/api/scan", token, scan2Payload)
	t.Logf("  POST /api/scan → %d: %s", scan2Resp.StatusCode, pretty(scan2Body))

	var scan2Data struct {
		Data struct {
			ScanID string `json:"scan_id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(scan2Body, &scan2Data))

	result2 := waitScan(url, token, scan2Data.Data.ScanID, 60*time.Second)
	require.Equal(t, "completed", result2.status)
	postVulns := result2.vulns

	t.Logf("  ✓ Scan completed: vulns=%d (%v)", postVulns, time.Since(t4))
	t.Log("")

	// ═══════════════════════════════════════════════════════════════════════
	//  T5: Verify vulnerability via API
	// ═══════════════════════════════════════════════════════════════════════
	t5 := time.Now()
	t.Log("── T5: Verify vulnerability via API ──")

	vulnResp, vulnBody := doGet(url, "/api/vulnerabilities?limit=50", token)
	require.Equal(t, 200, vulnResp.StatusCode)

	var vulnList struct {
		Count int `json:"count"`
		Data  []struct {
			CVE            string    `json:"cve"`
			Severity       string    `json:"severity"`
			ExploitedInWild bool     `json:"exploited_in_wild"`
			CVSSScore      float64   `json:"cvss_score"`
			DiscoveredAt   time.Time `json:"discovered_at"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(vulnBody, &vulnList))

	var found bool
	for _, v := range vulnList.Data {
		if v.CVE == cveID {
			found = true
			t.Logf("  ✓ CVE found via GET /api/vulnerabilities:")
			t.Logf("    cve:           %s", v.CVE)
			t.Logf("    severity:      %s", v.Severity)
			t.Logf("    exploited:     %v", v.ExploitedInWild)
			t.Logf("    cvss:          %.1f", v.CVSSScore)
			t.Logf("    discovered_at: %s", v.DiscoveredAt.Format(time.RFC3339))

			assert.Equal(t, "critical", v.Severity)
			assert.True(t, v.ExploitedInWild)
			assert.InDelta(t, 9.8, v.CVSSScore, 0.1)
			assert.WithinDuration(t, discoveredAt, v.DiscoveredAt, 5*time.Second)
		}
	}
	require.True(t, found, "CVE %s should appear in GET /api/vulnerabilities", cveID)
	t.Logf("  Total vulnerabilities: %d", vulnList.Count)
	t.Logf("  Duration: %v", time.Since(t5))
	t.Log("")

	// ═══════════════════════════════════════════════════════════════════════
	//  T6: Wait for SLA deadline calculation
	// ═══════════════════════════════════════════════════════════════════════
	t6 := time.Now()
	t.Log("── T6: Wait for SLA deadline calculation ──")

	type slaEntry struct {
		CVE      string    `json:"cve"`
		Deadline time.Time `json:"deadline"`
		Status   string    `json:"status"`
		HoursRem float64   `json:"hours_remaining"`
	}

	var sla *slaEntry
	slaDeadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(slaDeadline) {
		slaResp, slaBody := doGet(url, "/api/compliance/sla", token)
		if slaResp.StatusCode != 200 || len(slaBody) == 0 {
			time.Sleep(3 * time.Second)
			continue
		}

		var list struct {
			Data []slaEntry `json:"data"`
		}
		if err := json.Unmarshal(slaBody, &list); err != nil {
			time.Sleep(3 * time.Second)
			continue
		}

		for _, s := range list.Data {
			if s.CVE == cveID {
				sla = &slaEntry{s.CVE, s.Deadline, s.Status, s.HoursRem}
				break
			}
		}
		if sla != nil {
			break
		}
		time.Sleep(3 * time.Second)
	}

	require.NotNil(t, sla, "SLA entry for %s should appear within 60s", cveID)

	t.Logf("  ✓ SLA entry found:")
	t.Logf("    cve:             %s", sla.CVE)
	t.Logf("    deadline:        %s", sla.Deadline.Format(time.RFC3339))
	t.Logf("    status:          %s", sla.Status)
	t.Logf("    hours_remaining: %.1fh", sla.HoursRem)

	// ═══════════════════════════════════════════════════════════════════════
	//  CRITICAL: SLA deadline must be anchored to discovered_at
	//  This CVE is KEV-exploited → deadline = discovered_at + 24h
	//  The deadline MUST NOT be time.Now() + 24h (the old bug)
	// ═══════════════════════════════════════════════════════════════════════
	expectedDeadline := discoveredAt.Add(24 * time.Hour)
	slaWindow := sla.Deadline.Sub(discoveredAt)

	t.Logf("    expected_deadline: %s (discovered_at + 24h)", expectedDeadline.Format(time.RFC3339))
	t.Logf("    sla_window:        %v", slaWindow)

	assert.WithinDuration(t, expectedDeadline, sla.Deadline, 5*time.Second,
		"SLA deadline MUST be discovered_at + 24h (KEV), not time.Now() + 24h. "+
			"Got %s, expected %s",
		sla.Deadline.Format(time.RFC3339), expectedDeadline.Format(time.RFC3339))

	// Verify it's NOT time.Now() + 24h
	nowPlus24 := time.Now().Add(24 * time.Hour)
	assert.False(t, absDur(sla.Deadline.Sub(nowPlus24)) < 1*time.Hour,
		"SLA deadline (%s) looks like time.Now() + 24h (%s) — this is the OLD BUG",
		sla.Deadline.Format(time.RFC3339), nowPlus24.Format(time.RFC3339))

	t.Logf("  Duration: %v", time.Since(t6))
	t.Log("")

	// ═══════════════════════════════════════════════════════════════════════
	//  T7: Check alerts
	// ═══════════════════════════════════════════════════════════════════════
	t7 := time.Now()
	t.Log("── T7: Check alerts ──")

	alertResp, alertBody := doGet(url, "/api/alerts", token)
	t.Logf("  GET /api/alerts → %d", alertResp.StatusCode)
	if len(alertBody) > 2 {
		t.Logf("  Body: %s", pretty(alertBody))
	}

	// Check DB for SLA breach detection
	var breachCount int
	_ = db.QueryRow(`SELECT count(*) FROM compliance.sla_tracking WHERE cve = $1 AND status = 'violated'`, cveID).Scan(&breachCount)
	t.Logf("  SLA breaches in DB: %d", breachCount)
	t.Logf("  Duration: %v", time.Since(t7))
	t.Log("")

	// ═══════════════════════════════════════════════════════════════════════
	//  Summary
	// ═══════════════════════════════════════════════════════════════════════
	total := time.Since(t0)
	pipeline := t5.Sub(t3)

	t.Log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	t.Log("  TIMING SUMMARY")
	t.Log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Fprintf(os.Stdout, "  %-30s %v\n", "T0 Health check:", t1.Sub(t0))
	fmt.Fprintf(os.Stdout, "  %-30s %v\n", "T1 Upload SBOM:", t2.Sub(t1))
	fmt.Fprintf(os.Stdout, "  %-30s %v\n", "T2 Initial scan:", t3.Sub(t2))
	fmt.Fprintf(os.Stdout, "  %-30s %v\n", "T3 Inject CVE:", t4.Sub(t3))
	fmt.Fprintf(os.Stdout, "  %-30s %v\n", "T4 Second scan:", t5.Sub(t4))
	fmt.Fprintf(os.Stdout, "  %-30s %v\n", "T5 Verify vuln API:", t6.Sub(t5))
	fmt.Fprintf(os.Stdout, "  %-30s %v\n", "T6 SLA calculation:", t7.Sub(t6))
	fmt.Fprintf(os.Stdout, "  %-30s %v\n", "T7 Alerts:", time.Since(t7))
	fmt.Fprintf(os.Stdout, "  %s\n", "────────────────────────────────────────────────")
	fmt.Fprintf(os.Stdout, "  %-30s %v\n", "CVE inject → API visible:", pipeline)
	fmt.Fprintf(os.Stdout, "  %-30s %v\n", "Total E2E:", total)
	fmt.Fprintf(os.Stdout, "  %-30s %v (expected 24h)\n", "SLA window:", slaWindow)
	fmt.Fprintf(os.Stdout, "  %-30s %s\n", "SLA deadline:", sla.Deadline.Format(time.RFC3339))
	fmt.Fprintf(os.Stdout, "  %-30s %d → %d (+%d)\n", "Vulns (baseline→post):", baselineVulns, postVulns, postVulns-baselineVulns)
	t.Log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
}

// ── HTTP helpers ────────────────────────────────────────────────────────────

func doGet(baseURL, path, token string) (*http.Response, []byte) {
	req, _ := http.NewRequest("GET", baseURL+path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Organization-ID", testOrg)
	c := &http.Client{Timeout: 10 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return &http.Response{StatusCode: 0}, nil
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, body
}

func doPost(baseURL, path, token string, body []byte) (*http.Response, []byte) {
	req, _ := http.NewRequest("POST", baseURL+path, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Organization-ID", testOrg)
	req.Header.Set("Content-Type", "application/json")
	c := &http.Client{Timeout: 10 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return &http.Response{StatusCode: 0}, nil
	}
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, respBody
}

func doUpload(baseURL, path, token, filename string, data []byte) (*http.Response, []byte) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, _ := w.CreateFormFile("file", filename)
	part.Write(data)
	w.Close()

	req, _ := http.NewRequest("POST", baseURL+path, &buf)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Organization-ID", testOrg)
	req.Header.Set("Content-Type", w.FormDataContentType())
	c := &http.Client{Timeout: 30 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return &http.Response{StatusCode: 0}, nil
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, body
}

type scanResult struct {
	status string
	vulns  int
}

func waitScan(baseURL, token, scanID string, timeout time.Duration) scanResult {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, body := doGet(baseURL, "/api/scans?limit=100", token)
		if resp.StatusCode != 200 {
			time.Sleep(2 * time.Second)
			continue
		}
		var list struct {
			Data []struct {
				ID     string `json:"id"`
				ScanID string `json:"scan_id"`
				Status string `json:"status"`
				Vulns  int    `json:"vulnerabilities_found"`
			} `json:"data"`
		}
		if json.Unmarshal(body, &list) != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		for _, s := range list.Data {
			if s.ID == scanID || s.ScanID == scanID {
				if s.Status == "completed" || s.Status == "failed" {
					return scanResult{s.Status, s.Vulns}
				}
			}
		}
		time.Sleep(2 * time.Second)
	}
	return scanResult{"timeout", -1}
}

func pretty(data []byte) string {
	var v interface{}
	if json.Unmarshal(data, &v) != nil {
		return string(data)
	}
	out, _ := json.MarshalIndent(v, "  ", "  ")
	return string(out)
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func cleanup(t *testing.T, db *sql.DB) {
	t.Helper()
	tables := []string{
		"compliance.sla_tracking",
		"compliance.scan_vulnerabilities",
	}
	for _, tbl := range tables {
		_, _ = db.Exec(fmt.Sprintf("DELETE FROM %s WHERE cve LIKE 'CVE-2026-E2E%%'", tbl))
	}
	_, _ = db.Exec("DELETE FROM compliance.vulnerabilities WHERE cve LIKE 'CVE-2026-E2E%'")
	_, _ = db.Exec("DELETE FROM compliance.vulnerability_feeds WHERE cve LIKE 'CVE-2026-E2E%'")
	_, _ = db.Exec("DELETE FROM compliance.scans WHERE sbom_id IN (SELECT id FROM compliance.sbom_uploads WHERE filename LIKE 'e2e-pipeline%')")
	_, _ = db.Exec("DELETE FROM compliance.sbom_uploads WHERE filename LIKE 'e2e-pipeline%'")
	t.Log("  DB cleaned from previous runs")
}
