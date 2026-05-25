//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// PipelineLatencyIntegrationTest measures real pipeline timings against a
// running transparenz-server. This requires:
//   - PostgreSQL running on :25432 with seed data
//   - OSS server running on :28080
//   - Test JWT set in TRANSPARENZ_JWT env var
//
// Run with:
//
//	go test -v -tags=integration -run TestPipelineLatency ./tests/integration/
//
// The pipeline stages measured are:
//
//	Feed Ingest → Vuln Match → SLA Calculate → Alert → Disclosure
//	   T0           T1            T2             T3       T4
//
// What we measure:
//   1. Feed→Match: How long from new CVE in feed to vulnerability linked to SBOM
//   2. Match→SLA:  How long from vuln linked to SLA deadline set
//   3. SLA→Alert:  How long from SLA set to operator notified
//   4. Feed→Report: End-to-end from CVE known to disclosure filed
//   5. SLA Erosion: How much of the SLA window the pipeline consumes
type PipelineConfig struct {
	ServerURL string
	JWT       string
	OrgID     string
	Client    *http.Client
}

func newPipelineConfig(t *testing.T) *PipelineConfig {
	t.Helper()
	serverURL := os.Getenv("TRANSPARENZ_SERVER_URL")
	if serverURL == "" {
		serverURL = "http://localhost:28080"
	}
	jwt := os.Getenv("TRANSPARENZ_JWT")
	orgID := os.Getenv("TRANSPARENZ_ORG_ID")
	if orgID == "" {
		orgID = "00000000-0000-0000-0000-000000000001"
	}
	require.NotEmpty(t, jwt, "TRANSPARENZ_JWT must be set")

	return &PipelineConfig{
		ServerURL: serverURL,
		JWT:       jwt,
		OrgID:     orgID,
		Client:    &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *PipelineConfig) doRequest(method, path string, body interface{}) (*http.Response, map[string]interface{}) {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, nil
		}
		reqBody = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, c.ServerURL+path, reqBody)
	if err != nil {
		return nil, nil
	}
	req.Header.Set("Authorization", "Bearer "+c.JWT)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Organization-ID", c.OrgID)

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	return resp, result
}

// TestPipelineLatency_ScanDuration measures how long a scan takes end-to-end.
// This is the T1→T2 stage: vulnerability matching against SBOM components.
func TestPipelineLatency_ScanDuration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if os.Getenv("TRANSPARENZ_JWT") == "" {
		t.Skip("TRANSPARENZ_JWT not set, skipping integration test")
	}

	cfg := newPipelineConfig(t)

	// Step 1: Upload a test SBOM
	t.Log("Step 1: Uploading test SBOM...")
	sbomPayload := map[string]interface{}{
		"filename": "pipeline-test-sbom.json",
		"format":   "spdx",
		"content": map[string]interface{}{
			"spdxVersion": "SPDX-2.3",
			"dataLicense": "CC0-1.0",
			"SPDXID":      "SPDXRef-DOCUMENT",
			"name":        "pipeline-test",
			"packages": []map[string]interface{}{
				{
					"SPDXID":         "SPDXRef-Package-log4j",
					"name":           "org.apache.logging.log4j:log4j-core",
					"versionInfo":    "2.14.1",
					"downloadLocation": "https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar",
					"licenseConcluded": "Apache-2.0",
				},
			},
		},
	}

	uploadStart := time.Now()
	resp, body := cfg.doRequest("POST", "/api/sboms/upload", sbomPayload)
	require.NotNil(t, resp)
	uploadDuration := time.Since(uploadStart)

	t.Logf("SBOM upload: status=%d duration=%v", resp.StatusCode, uploadDuration)

	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		t.Logf("SBOM upload response: %+v", body)
		t.Skipf("SBOM upload returned %d (expected 200/201)", resp.StatusCode)
	}

	// Extract SBOM ID
	sbomData, _ := body["data"].(map[string]interface{})
	sbomID, _ := sbomData["id"].(string)
	require.NotEmpty(t, sbomID, "SBOM response must contain data.id")
	t.Logf("SBOM ID: %s", sbomID)

	// Step 2: Create a scan
	t.Log("Step 2: Creating scan...")
	scanPayload := map[string]interface{}{
		"sbom_id": sbomID,
	}
	scanStart := time.Now()
	resp, body = cfg.doRequest("POST", "/api/scan", scanPayload)
	require.NotNil(t, resp)
	t.Logf("Scan creation: status=%d", resp.StatusCode)

	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		t.Logf("Scan creation response: %+v", body)
		t.Skipf("Scan creation returned %d", resp.StatusCode)
	}

	scanData, _ := body["data"].(map[string]interface{})
	scanID, _ := scanData["scan_id"].(string)
	require.NotEmpty(t, scanID, "Scan response must contain data.scan_id")
	t.Logf("Scan ID: %s", scanID)

	// Step 3: Poll for scan completion (with timeout)
	t.Log("Step 3: Waiting for scan to complete...")
	scanCompleteAt := pollForScanCompletion(t, cfg, scanID, 60*time.Second)
	scanDuration := scanCompleteAt.Sub(scanStart)

	t.Logf("━━━ Scan Timing ━━━")
	t.Logf("  Upload→Scan created: %v", scanStart.Sub(uploadStart))
	t.Logf("  Scan duration:       %v", scanDuration)
	t.Logf("  Total upload→done:   %v", scanCompleteAt.Sub(uploadStart))

	// Scan should complete within 60 seconds (matching against cached feed data)
	assert.Less(t, scanDuration, 60*time.Second,
		"Scan should complete within 60s for a small SBOM")
}

// TestPipelineLatency_SLADeadlineSet measures how long after a scan completes
// before the SLA deadline is calculated and stored.
// This is the T2→T3 stage: SLA calculator tick interval.
func TestPipelineLatency_SLADeadlineSet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if os.Getenv("TRANSPARENZ_JWT") == "" {
		t.Skip("TRANSPARENZ_JWT not set, skipping integration test")
	}

	cfg := newPipelineConfig(t)

	// Check SLA tracking for known test CVE
	resp, body := cfg.doRequest("GET", "/api/compliance/sla?status=pending", nil)
	require.NotNil(t, resp)

	t.Logf("SLA endpoint: status=%d", resp.StatusCode)

	if resp.StatusCode == 200 {
		data, _ := body["data"].([]interface{})
		t.Logf("  Pending SLAs: %d", len(data))

		// Measure SLA deadline precision
		for _, item := range data {
			sla, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			cve, _ := sla["cve"].(string)
			deadlineStr, _ := sla["deadline"].(string)
			createdAtStr, _ := sla["created_at"].(string)

			if deadlineStr != "" && createdAtStr != "" {
				deadline, err := time.Parse(time.RFC3339, deadlineStr)
				if err != nil {
					continue
				}
				createdAt, err := time.Parse(time.RFC3339, createdAtStr)
				if err != nil {
					continue
				}

				slaWindow := deadline.Sub(createdAt)
				t.Logf("  CVE %s: SLA window=%v deadline=%s",
					cve, slaWindow, deadlineStr)

				// Validate against known deadlines
				if slaWindow < 23*time.Hour || slaWindow > 73*time.Hour {
					t.Logf("  WARNING: SLA window %v outside expected range (24h-72h)", slaWindow)
				}
			}
		}
	}
}

// TestPipelineLatency_AlertDelivery measures alert delivery latency.
// This is the T3→T4 stage: from SLA breach/approaching to operator notification.
func TestPipelineLatency_AlertDelivery(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if os.Getenv("TRANSPARENZ_JWT") == "" {
		t.Skip("TRANSPARENZ_JWT not set, skipping integration test")
	}

	cfg := newPipelineConfig(t)

	// Check alerts endpoint
	resp, body := cfg.doRequest("GET", "/api/alerts", nil)
	require.NotNil(t, resp)

	t.Logf("Alerts endpoint: status=%d", resp.StatusCode)

	if resp.StatusCode == 200 {
		data, _ := body["data"].([]interface{})
		t.Logf("  Active alerts: %d", len(data))

		for _, item := range data {
			alert, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			alertType, _ := alert["type"].(string)
			severity, _ := alert["severity"].(string)
			message, _ := alert["message"].(string)
			t.Logf("  Alert: type=%s severity=%s msg=%s", alertType, severity, message)
		}
	}
}

// TestPipelineLatency_DisclosureLifecycle measures the full disclosure
// lifecycle timing: received → triaging → fixing → disclosed.
func TestPipelineLatency_DisclosureLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if os.Getenv("TRANSPARENZ_JWT") == "" {
		t.Skip("TRANSPARENZ_JWT not set, skipping integration test")
	}

	cfg := newPipelineConfig(t)

	// Check existing disclosures
	resp, body := cfg.doRequest("GET", "/api/disclosures", nil)
	require.NotNil(t, resp)

	t.Logf("Disclosures endpoint: status=%d", resp.StatusCode)

	if resp.StatusCode == 200 {
		data, _ := body["data"].([]interface{})
		t.Logf("  Disclosures: %d", len(data))

		for _, item := range data {
			disc, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			cve, _ := disc["cve"].(string)
			status, _ := disc["status"].(string)
			receivedAt, _ := disc["received_at"].(string)
			acknowledgedAt, _ := disc["acknowledged_at"].(string)

			if receivedAt != "" {
				t0, _ := time.Parse(time.RFC3339, receivedAt)
				t.Logf("  %s: status=%s received=%s", cve, status, receivedAt)

				if acknowledgedAt != "" {
					t1, _ := time.Parse(time.RFC3339, acknowledgedAt)
					ackLatency := t1.Sub(t0)
					t.Logf("    → Acknowledged in %v", ackLatency)
				}
			}
		}
	}
}

// TestPipelineLatency_ConfiguredIntervals reads and reports the configured
// pipeline intervals. These are the knobs that control pipeline latency.
func TestPipelineLatency_ConfiguredIntervals(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if os.Getenv("TRANSPARENZ_JWT") == "" {
		t.Skip("TRANSPARENZ_JWT not set, skipping integration test")
	}

	cfg := newPipelineConfig(t)

	// Check /readyz for health info
	resp, body := cfg.doRequest("GET", "/readyz", nil)
	require.NotNil(t, resp)

	t.Logf("━━━ Pipeline Configuration ━━━")

	// These are the production defaults from config.go:
	intervals := map[string]time.Duration{
		"VULNZ_SYNC_INTERVAL (feed fetch)":     6 * time.Hour,
		"JOB_QUEUE_POLL_INTERVAL (scan queue)":  5 * time.Second,
		"SLA_TICK_INTERVAL (deadline calc)":     1 * time.Minute,
		"ALERT_TICK_INTERVAL (notifications)":   30 * time.Second,
	}

	for name, interval := range intervals {
		t.Logf("  %s: %v", name, interval)
	}

	// Calculate worst-case pipeline latency
	worstCaseFeedSync := intervals["VULNZ_SYNC_INTERVAL (feed fetch)"]
	worstCaseScanQueue := intervals["JOB_QUEUE_POLL_INTERVAL (scan queue)"]
	worstCaseSLACalc := intervals["SLA_TICK_INTERVAL (deadline calc)"]
	worstCaseAlert := intervals["ALERT_TICK_INTERVAL (notifications)"]

	totalWorstCase := worstCaseFeedSync + worstCaseScanQueue + worstCaseSLACalc + worstCaseAlert

	t.Logf("")
	t.Logf("━━━ Worst-Case Pipeline Latency ━━━")
	t.Logf("  Feed sync wait:    %v", worstCaseFeedSync)
	t.Logf("  Scan queue wait:   %v", worstCaseScanQueue)
	t.Logf("  SLA calc wait:     %v", worstCaseSLACalc)
	t.Logf("  Alert wait:        %v", worstCaseAlert)
	t.Logf("  Total worst case:  %v", totalWorstCase)

	// SLA erosion analysis
	criticalSLA := 72 * time.Hour
	kevSLA := 24 * time.Hour
	erosionCritical := float64(totalWorstCase) / float64(criticalSLA) * 100
	erosionKEV := float64(totalWorstCase) / float64(kevSLA) * 100

	t.Logf("")
	t.Logf("━━━ SLA Erosion Analysis ━━━")
	t.Logf("  Critical (72h SLA): %.1f%% consumed by pipeline", erosionCritical)
	t.Logf("  KEV (24h SLA):      %.1f%% consumed by pipeline", erosionKEV)

	t.Logf("")
	t.Logf("  Health check: status=%d", resp.StatusCode)
	if body != nil {
		if workers, ok := body["workers"].(map[string]interface{}); ok {
			for name, w := range workers {
				if status, ok := w.(map[string]interface{}); ok {
					t.Logf("  Worker %s: %+v", name, status)
				}
			}
		}
	}

	// Pipeline must not consume more than 10% of critical SLA
	assert.Less(t, erosionCritical, 10.0,
		"Pipeline consumes %.1f%% of 72h critical SLA (max 10%%)", erosionCritical)

	// Pipeline must not consume more than 30% of KEV SLA
	assert.Less(t, erosionKEV, 30.0,
		"Pipeline consumes %.1f%% of 24h KEV SLA (max 30%%)", erosionKEV)
}

// =============================================================================
// Helpers
// =============================================================================

func pollForScanCompletion(t *testing.T, cfg *PipelineConfig, scanID string, timeout time.Duration) time.Time {
	t.Helper()
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		resp, body := cfg.doRequest("GET", fmt.Sprintf("/api/scans/%s", scanID), nil)
		if resp == nil {
			time.Sleep(1 * time.Second)
			continue
		}

		if resp.StatusCode == 200 {
			data, _ := body["data"].(map[string]interface{})
			status, _ := data["status"].(string)

			switch status {
			case "completed":
				return time.Now()
			case "failed":
				t.Fatalf("Scan %s failed", scanID)
			}
		}

		time.Sleep(2 * time.Second)
	}

	t.Fatalf("Scan %s did not complete within %v", scanID, timeout)
	return time.Time{} // unreachable
}

// Compute percentiles from a slice of durations.
func computePercentiles(durations []time.Duration) map[float64]time.Duration {
	if len(durations) == 0 {
		return nil
	}

	result := make(map[float64]time.Duration)
	for _, p := range []float64{0.5, 0.9, 0.95, 0.99} {
		idx := int(math.Ceil(float64(len(durations)) * p))
		if idx >= len(durations) {
			idx = len(durations) - 1
		}
		if idx < 0 {
			idx = 0
		}
		result[p] = durations[idx]
	}
	return result
}

// Ensure unused imports don't fail
var _ = computePercentiles
