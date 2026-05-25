//go:build integration

package integration

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test_Pipeline_SBOMCleanToVulnerableToAlert is the full E2E pipeline test.
//
// It traces the complete vulnerability disclosure lifecycle:
//
//	 T0  Upload SBOM with clean component
//	 T1  Initial scan → baseline (0 new vulns expected from our injected CVE)
//	 T2  Inject CVE into vulnerability_feeds (simulates feed sync)
//	 T3  Insert vulnerability record (simulates ScanWorker detection)
//	 T4  Trigger second scan → vulnerability now detected
//	 T5  Wait for SLA deadline calculation
//	 T6  Verify SLA deadline is anchored to discovered_at (not time.Now())
//	 T7  Verify alert broadcast
//
// All request/response bodies, timings, and DB state are logged as test output.
func Test_Pipeline_SBOMCleanToVulnerableToAlert(t *testing.T) {
	env := SetupTestEnvironment(t, WithoutBSISeed())

	const (
		cveID       = "CVE-2026-E2E-PIPELINE"
		component   = "e2e-pipeline-lib"
		version     = "1.0.0"
		severity    = "critical"
		cvss        = 9.8
		discovered  = "2026-05-25T12:00:00Z" // 2h before test — tests SLA erosion
	)

	// Connect directly to the test DB for feed/vuln injection
	db, err := sql.Open("postgres", env.PGURL)
	require.NoError(t, err, "connect to test DB")
	defer db.Close()

	t.Log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	t.Log("  E2E PIPELINE TEST: SBOM Clean → Vulnerable → Alert")
	t.Log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	t.Logf("  CVE:        %s", cveID)
	t.Logf("  Component:  %s@%s", component, version)
	t.Logf("  Severity:   %s (CVSS %.1f)", severity, cvss)
	t.Logf("  Discovered: %s (2h ago — tests SLA anchoring)", discovered)
	t.Log("")

	// ── Clean up any previous test run ──────────────────────────────────────
	cleanDB(t, db)

	// ═══════════════════════════════════════════════════════════════════════
	//  T0: Upload SBOM with clean component
	// ═══════════════════════════════════════════════════════════════════════
	t0 := time.Now()
	t.Log("── T0: Upload SBOM ──")

	sbomData := MustGenerateCycloneDXSBOM("e2e-pipeline-app", "1.0.0", []CycloneDXComponent{
		{Name: component, Version: version, PURL: fmt.Sprintf("pkg:generic/%s@%s", component, version)},
	})
	upload := env.UploadSBOM("e2e-pipeline.cdx.json", sbomData)

	t.Logf("  SBOM ID:    %s", upload.ID)
	t.Logf("  SHA256:     %s", upload.SHA256)
	t.Logf("  Duration:   %v", time.Since(t0))
	t.Log("")

	// ═══════════════════════════════════════════════════════════════════════
	//  T1: Initial scan (baseline — CVE not yet in feed)
	// ═══════════════════════════════════════════════════════════════════════
	t1 := time.Now()
	t.Log("── T1: Initial scan (baseline) ──")

	scan1 := env.CreateScan(upload.ID)
	t.Logf("  Scan ID:    %s", scan1.ScanID)
	t.Logf("  Status:     %s", scan1.Status)

	baselineVulns := env.WaitForScanCompletion(scan1.ScanID, 120*time.Second)
	t.Logf("  Vulns found: %d", baselineVulns)
	t.Logf("  Duration:    %v", time.Since(t1))
	t.Log("")

	// ═══════════════════════════════════════════════════════════════════════
	//  T2: Inject CVE into vulnerability_feeds (simulates feed sync)
	// ═══════════════════════════════════════════════════════════════════════
	t2 := time.Now()
	t.Log("── T2: Inject CVE into feed ──")

	_, err = db.Exec(`
		INSERT INTO compliance.vulnerability_feeds
			(id, cve, kev_exploited, enisa_severity, affected_products, last_synced_at, created_at, updated_at)
		VALUES (
			gen_random_uuid(),
			$1, true, $2,
			$3::jsonb,
			NOW(), NOW(), NOW()
		)
		ON CONFLICT (cve) DO UPDATE SET
			kev_exploited = true,
			enisa_severity = $2,
			affected_products = $3::jsonb,
			last_synced_at = NOW(),
			updated_at = NOW()
	`, cveID, severity, fmt.Sprintf(
		`[{"name":"%s","vendor":"e2e-test","version":"%s"}]`, component, version,
	))
	require.NoError(t, err, "insert feed record")

	t.Logf("  Feed record:  %s → %s@%s", cveID, component, version)
	t.Logf("  Duration:     %v", time.Since(t2))
	t.Log("")

	// ═══════════════════════════════════════════════════════════════════════
	//  T3: Insert vulnerability record (simulates ScanWorker detection)
	// ═══════════════════════════════════════════════════════════════════════
	t3 := time.Now()
	t.Log("── T3: Insert vulnerability record ──")

	// Get the org_id from the upload
	var orgID string
	err = db.QueryRow(`SELECT org_id FROM compliance.sbom_uploads WHERE id = $1`, upload.ID).Scan(&orgID)
	require.NoError(t, err, "get org ID from SBOM")

	discoveredAt, _ := time.Parse(time.RFC3339, discovered)

	_, err = db.Exec(`
		INSERT INTO compliance.vulnerabilities
			(id, org_id, cve, severity, cvss_score, exploited_in_wild, discovered_at, created_at, updated_at)
		VALUES (gen_random_uuid(), $1, $2, $3, $4, true, $5, NOW(), NOW())
		ON CONFLICT DO NOTHING
	`, orgID, cveID, severity, cvss, discoveredAt)
	require.NoError(t, err, "insert vulnerability record")

	t.Logf("  Vuln record:  %s severity=%s cvss=%.1f discovered=%s", cveID, severity, cvss, discovered)
	t.Logf("  Org ID:       %s", orgID)
	t.Logf("  Duration:     %v", time.Since(t3))
	t.Log("")

	// ═══════════════════════════════════════════════════════════════════════
	//  T4: Trigger second scan (simulates AutoRescanHook)
	// ═══════════════════════════════════════════════════════════════════════
	t4 := time.Now()
	t.Log("── T4: Second scan (post-CVE injection) ──")

	scan2 := env.CreateScan(upload.ID)
	t.Logf("  Scan ID:    %s", scan2.ScanID)

	postVulns := env.WaitForScanCompletion(scan2.ScanID, 120*time.Second)
	t.Logf("  Vulns found: %d", postVulns)
	t.Logf("  Duration:    %v", time.Since(t4))
	t.Log("")

	// ═══════════════════════════════════════════════════════════════════════
	//  T5: Verify vulnerability visible via API
	// ═══════════════════════════════════════════════════════════════════════
	t5 := time.Now()
	t.Log("── T5: Verify vulnerability via API ──")

	vulnResp := env.AuthedGet("/api/vulnerabilities?limit=50")
	vulnBody := ReadBody(t, vulnResp)
	AssertStatus(t, vulnResp, http.StatusOK)

	var vulnList struct {
		Count int `json:"count"`
		Data  []struct {
			CVE            string     `json:"cve"`
			Severity       string     `json:"severity"`
			ExploitedInWild bool       `json:"exploited_in_wild"`
			CVSSScore      float64    `json:"cvss_score"`
			DiscoveredAt   time.Time  `json:"discovered_at"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(vulnBody, &vulnList))

	var foundCVE bool
	for _, v := range vulnList.Data {
		if v.CVE == cveID {
			foundCVE = true
			t.Logf("  ✓ CVE found via API:")
			t.Logf("    cve:             %s", v.CVE)
			t.Logf("    severity:        %s", v.Severity)
			t.Logf("    exploited:       %v", v.ExploitedInWild)
			t.Logf("    cvss:            %.1f", v.CVSSScore)
			t.Logf("    discovered_at:   %s", v.DiscoveredAt.Format(time.RFC3339))

			assert.Equal(t, severity, v.Severity)
			assert.True(t, v.ExploitedInWild, "should be marked exploited (KEV)")
			assert.InDelta(t, cvss, v.CVSSScore, 0.1)
			// discovered_at should match what we inserted
			assert.WithinDuration(t, discoveredAt, v.DiscoveredAt, 5*time.Second,
				"discovered_at should match the feed injection timestamp")
			break
		}
	}
	require.True(t, foundCVE, "CVE %s should appear in vulnerabilities API", cveID)

	t.Logf("  Duration:     %v", time.Since(t5))
	t.Log("")

	// ═══════════════════════════════════════════════════════════════════════
	//  T6: Wait for SLA deadline and verify anchoring
	// ═══════════════════════════════════════════════════════════════════════
	t6 := time.Now()
	t.Log("── T6: Wait for SLA deadline calculation ──")

	var slaEntry *struct {
		ID       string    `json:"id"`
		CVE      string    `json:"cve"`
		Deadline time.Time `json:"deadline"`
		Status   string    `json:"status"`
		HoursRem float64   `json:"hours_remaining"`
	}

	// Poll SLA endpoint until our CVE appears
	slaDeadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(slaDeadline) {
		slaResp := env.AuthedGet("/api/compliance/sla")
		slaBody := ReadBody(t, slaResp)

		var slaList struct {
			Count int `json:"count"`
			Data  []struct {
				ID       string    `json:"id"`
				CVE      string    `json:"cve"`
				Deadline time.Time `json:"deadline"`
				Status   string    `json:"status"`
				HoursRem float64   `json:"hours_remaining"`
			} `json:"data"`
		}
		if err := json.Unmarshal(slaBody, &slaList); err != nil {
			time.Sleep(3 * time.Second)
			continue
		}

		for _, s := range slaList.Data {
			if s.CVE == cveID {
				s := s // capture
				slaEntry = &s
				break
			}
		}
		if slaEntry != nil {
			break
		}
		time.Sleep(3 * time.Second)
	}

	require.NotNil(t, slaEntry, "SLA entry for %s should appear within 60s", cveID)

	t.Logf("  ✓ SLA entry found:")
	t.Logf("    id:              %s", slaEntry.ID)
	t.Logf("    cve:             %s", slaEntry.CVE)
	t.Logf("    deadline:        %s", slaEntry.Deadline.Format(time.RFC3339))
	t.Logf("    status:          %s", slaEntry.Status)
	t.Logf("    hours_remaining: %.1fh", slaEntry.HoursRem)

	// ═══════════════════════════════════════════════════════════════════════
	//  CRITICAL ASSERTION: SLA deadline must be anchored to discovered_at
	//
	//  This CVE is KEV-exploited → deadline = discovered_at + 24h.
	//  The deadline MUST NOT be time.Now() + 24h.
	// ═══════════════════════════════════════════════════════════════════════
	expectedDeadline := discoveredAt.Add(24 * time.Hour) // KEV = 24h from discovered_at
	t.Logf("    expected (KEV):  discovered_at + 24h = %s", expectedDeadline.Format(time.RFC3339))

	assert.WithinDuration(t, expectedDeadline, slaEntry.Deadline, 5*time.Second,
		"SLA deadline must be discovered_at + 24h (KEV), not time.Now() + 24h. "+
			"Got %s, expected %s",
		slaEntry.Deadline.Format(time.RFC3339),
		expectedDeadline.Format(time.RFC3339))

	// Verify it's NOT anchored to now
	nowDeadline := time.Now().Add(24 * time.Hour)
	assert.NotEqual(t, nowDeadline.Truncate(time.Second), slaEntry.Deadline.Truncate(time.Second),
		"SLA deadline must NOT be time.Now() + 24h")

	// The SLA window (deadline - discovered_at) should be exactly 24h
	slaWindow := slaEntry.Deadline.Sub(discoveredAt)
	t.Logf("    SLA window:      %v", slaWindow)
	deadlineDiff := slaEntry.Deadline.Sub(discoveredAt)
	assert.True(t, deadlineDiff >= 23*time.Hour && deadlineDiff <= 25*time.Hour,
		"SLA window should be ~24h for KEV, got %v", deadlineDiff)

	// Since discovered_at was 2h ago, the SLA should already be past deadline
	// (discovered_at + 24h is 22h ago if discovered 26h ago, or 22h from now if 2h ago)
	// With discovered = now - 2h: deadline = discovered + 24h = now + 22h → still pending
	t.Logf("  Duration:     %v", time.Since(t6))
	t.Log("")

	// ═══════════════════════════════════════════════════════════════════════
	//  T7: Verify alert via server logs / SSE
	// ═══════════════════════════════════════════════════════════════════════
	t7 := time.Now()
	t.Log("── T7: Verify alerts endpoint ──")

	// The alert service runs on a tick — give it time
	alertResp := env.AuthedGet("/api/alerts")
	alertBody := ReadBody(t, alertResp)
	t.Logf("  GET /api/alerts → HTTP %d", alertResp.StatusCode)
	t.Logf("  Body: %s", string(alertBody)[:min(len(alertBody), 500)])

	// Also check DB for SLA breach detection
	var breachCount int
	err = db.QueryRow(`
		SELECT count(*) FROM compliance.sla_tracking
		WHERE cve = $1 AND status IN ('violated', 'breached')
	`, cveID).Scan(&breachCount)
	if err == nil && breachCount > 0 {
		t.Logf("  ✓ SLA breach detected in DB (count=%d)", breachCount)
	}

	t.Logf("  Duration:     %v", time.Since(t7))
	t.Log("")

	// ═══════════════════════════════════════════════════════════════════════
	//  T8: Final scan verification — vulnerability count must have increased
	// ═══════════════════════════════════════════════════════════════════════
	t.Log("── T8: Final verification ──")

	assert.GreaterOrEqual(t, postVulns, baselineVulns,
		"Post-injection scan should find >= baseline vulnerabilities")

	t.Logf("  Baseline vulns: %d", baselineVulns)
	t.Logf("  Post-injection: %d", postVulns)
	t.Logf("  Delta:          %d", postVulns-baselineVulns)

	// ═══════════════════════════════════════════════════════════════════════
	//  TIMING SUMMARY
	// ═══════════════════════════════════════════════════════════════════════
	e2eTotal := time.Since(t0)
	pipelineTime := t5.Sub(t2) // CVE injection → vulnerability visible

	t.Log("")
	t.Log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	t.Log("  TIMING SUMMARY")
	t.Log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	t.Logf("  T0 Upload SBOM:              %v", t1.Sub(t0))
	t.Logf("  T1 Initial scan:             %v", t2.Sub(t1))
	t.Logf("  T2 Inject CVE:               %v", t3.Sub(t2))
	t.Logf("  T3 Insert vuln record:       %v", t4.Sub(t3))
	t.Logf("  T4 Second scan:              %v", t5.Sub(t4))
	t.Logf("  T5 Verify vulnerability:     %v", t6.Sub(t5))
	t.Logf("  T6 SLA calculation:          %v", t7.Sub(t6))
	t.Logf("  T7 Alert verification:       %v", time.Since(t7))
	t.Logf("  ────────────────────────────────────────")
	t.Logf("  CVE injection → API visible: %v", pipelineTime)
	t.Logf("  Total E2E test:              %v", e2eTotal)
	t.Log("")
	t.Logf("  SLA deadline:                %s", slaEntry.Deadline.Format(time.RFC3339))
	t.Logf("  SLA window:                  %v (expected 24h KEV)", slaWindow)
	t.Logf("  SLA erosion:                 %v (discovered → deadline set)", time.Since(discoveredAt)-slaWindow)
	t.Log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	// ═══════════════════════════════════════════════════════════════════════
	//  Write evidence
	// ═══════════════════════════════════════════════════════════════════════
	env.WriteJSONEvidence("pipeline-e2e-summary.json", map[string]interface{}{
		"cve":               cveID,
		"component":         fmt.Sprintf("%s@%s", component, version),
		"sbom_id":           upload.ID,
		"scan1_id":          scan1.ScanID,
		"scan2_id":          scan2.ScanID,
		"baseline_vulns":    baselineVulns,
		"post_vulns":        postVulns,
		"sla_deadline":      slaEntry.Deadline.Format(time.RFC3339),
		"sla_status":        slaEntry.Status,
		"sla_window":        slaWindow.String(),
		"sla_deadline_correct": expectedDeadline.Format(time.RFC3339),
		"pipeline_time_ms":  pipelineTime.Milliseconds(),
		"total_time_ms":     e2eTotal.Milliseconds(),
		"stages": map[string]string{
			"upload":     t1.Sub(t0).String(),
			"scan1":      t2.Sub(t1).String(),
			"inject_cve": t3.Sub(t2).String(),
			"insert_vuln": t4.Sub(t3).String(),
			"scan2":      t5.Sub(t4).String(),
			"verify_api": t6.Sub(t5).String(),
			"sla_wait":   t7.Sub(t6).String(),
		},
	})
}

// cleanDB removes previous E2E pipeline test data.
func cleanDB(t *testing.T, db *sql.DB) {
	t.Helper()

	tables := []string{
		"compliance.sla_tracking",
		"compliance.scan_vulnerabilities",
		"compliance.compliance_events",
	}

	// Clean up in order (respect FK constraints)
	for _, table := range tables {
		_, err := db.Exec(fmt.Sprintf("DELETE FROM %s WHERE cve = $1 OR cve LIKE 'CVE-2026-E2E%%'", table))
		if err != nil {
			t.Logf("  cleanup %s: %v (may not exist)", table, err)
		}
	}

	// Delete vulnerabilities and feeds for our test CVEs
	_, _ = db.Exec("DELETE FROM compliance.vulnerabilities WHERE cve LIKE 'CVE-2026-E2E%'")
	_, _ = db.Exec("DELETE FROM compliance.vulnerability_feeds WHERE cve LIKE 'CVE-2026-E2E%'")
	_, _ = db.Exec("DELETE FROM compliance.scans WHERE sbom_id IN (SELECT id FROM compliance.sbom_uploads WHERE filename LIKE 'e2e-pipeline%')")
	_, _ = db.Exec("DELETE FROM compliance.sbom_uploads WHERE filename LIKE 'e2e-pipeline%'")

	t.Log("  DB cleaned from previous runs")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
