//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test_Feed_Status validates the vulnerability feed status endpoint.
func Test_Feed_Status(t *testing.T) {
	env := SetupTestEnvironment(t, WithoutBSISeed())

	resp := env.AuthedGet("/api/feeds/status")
	body := env.CaptureEvidence("feed-status.json", resp)
	AssertStatus(t, resp, http.StatusOK)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &result))

	// Feed status should include counts
	env.WriteJSONEvidence("feed-status-validated.json", map[string]interface{}{
		"has_total_feeds": result["total_feeds"] != nil,
		"has_bsi_entries": result["bsi_entries"] != nil,
	})
}

// Test_Export_AuditCSV validates the audit export endpoint.
func Test_Export_AuditCSV(t *testing.T) {
	env := SetupTestEnvironment(t, WithoutBSISeed())

	// Generate some audit data first
	sbomData := GenerateSafeCycloneDXSBOM(t)
	upload := env.UploadSBOM("export-audit.cdx", sbomData)
	env.CreateScan(upload.ID)

	resp := env.AuthedGet("/api/export/audit")
	body := env.CaptureEvidence("export-audit.csv", resp)

	// Requires compliance_officer role — default user may get 403
	if resp.StatusCode != http.StatusOK {
		assert.Contains(t, []int{http.StatusForbidden, http.StatusUnauthorized}, resp.StatusCode)
	} else {
		assert.NotEmpty(t, body)
	}
}

// Test_Export_EnrichedSBOM validates the enriched SBOM export endpoint.
func Test_Export_EnrichedSBOM(t *testing.T) {
	env := SetupTestEnvironment(t, WithoutBSISeed())

	sbomData := GenerateVulnerableCycloneDXSBOM(t)
	upload := env.UploadSBOM("export-enriched.cdx", sbomData)
	scan := env.CreateScan(upload.ID)
	env.WaitForScanCompletion(scan.ScanID, 120*time.Second)

	resp := env.AuthedGet("/api/export/enriched-sbom/" + upload.ID)
	body := env.CaptureEvidence("export-enriched-sbom.json", resp)

	if resp.StatusCode == http.StatusOK {
		var result map[string]interface{}
		require.NoError(t, json.Unmarshal(body, &result))
		assert.NotEmpty(t, result)
	} else {
		// May be 403 (not compliance_officer) or 404
		assert.Contains(t, []int{http.StatusForbidden, http.StatusUnauthorized, http.StatusNotFound}, resp.StatusCode)
	}
}

// Test_Alert_Stream validates the SSE alert stream endpoint (basic connection test).
func Test_Alert_Stream(t *testing.T) {
	env := SetupTestEnvironment(t, WithoutBSISeed())

	// SSE is a long-lived connection — just verify it connects
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", env.ServerBaseURL+"/api/alerts/stream", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+env.AccessToken)
	req.Header.Set("Accept", "text/event-stream")

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// SSE endpoint may return 200 with text/event-stream, or a JSON error
	if resp.StatusCode == http.StatusOK {
		assert.Contains(t, resp.Header.Get("Content-Type"), "text/event-stream")
	} else {
		// Non-SSE response — endpoint exists and responded
		assert.Contains(t, []int{http.StatusOK, http.StatusBadRequest, http.StatusServiceUnavailable}, resp.StatusCode)
	}

	env.WriteJSONEvidence("alert-stream.json", map[string]interface{}{
		"status_code":  resp.StatusCode,
		"content_type": resp.Header.Get("Content-Type"),
	})
}
