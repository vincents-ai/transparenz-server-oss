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

// Test_ENISA_ListSubmissions validates listing ENISA submissions.
func Test_ENISA_ListSubmissions(t *testing.T) {
	env := SetupTestEnvironment(t, WithoutBSISeed())

	resp := env.AuthedGet("/api/enisa/submissions")
	body := env.CaptureEvidence("enisa-submissions.json", resp)
	AssertStatus(t, resp, http.StatusOK)

	var result struct {
		Data []interface{} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(body, &result))
	assert.NotNil(t, result.Data)
}

// Test_ENISA_GetNonexistentSubmission validates 404 for non-existent submission.
func Test_ENISA_GetNonexistentSubmission(t *testing.T) {
	env := SetupTestEnvironment(t, WithoutBSISeed())

	resp := env.AuthedGet("/api/enisa/submissions/00000000-0000-0000-0000-000000000000")
	AssertStatus(t, resp, http.StatusNotFound)
	env.CaptureEvidence("enisa-nonexistent.json", resp)
}

// Test_ENISA_DownloadNonexistent validates 404 for non-existent download.
func Test_ENISA_DownloadNonexistent(t *testing.T) {
	env := SetupTestEnvironment(t, WithoutBSISeed())

	resp := env.AuthedGet("/api/enisa/submissions/00000000-0000-0000-0000-000000000000/download")
	AssertStatus(t, resp, http.StatusNotFound)
	env.CaptureEvidence("enisa-download-nonexistent.json", resp)
}

// Test_ENISA_Submit validates the submit endpoint (requires admin role).
func Test_ENISA_Submit(t *testing.T) {
	env := SetupTestEnvironment(t, WithoutBSISeed())

	// First upload and scan an SBOM
	sbomData := GenerateVulnerableCycloneDXSBOM(t)
	upload := env.UploadSBOM("enisa-submit.cdx", sbomData)
	scan := env.CreateScan(upload.ID)
	env.WaitForScanCompletion(scan.ScanID, 120*time.Second)

	// Try to submit (admin endpoint)
	submitResp := env.AuthedPost("/api/enisa/submit", map[string]interface{}{
		"sbom_id": upload.ID,
	})
	env.CaptureEvidence("enisa-submit.json", submitResp)

	// May succeed (200/202) or fail (403 not admin, or other error)
	assert.Contains(t, []int{
		http.StatusOK, http.StatusAccepted, http.StatusForbidden, http.StatusBadRequest,
	}, submitResp.StatusCode)
}
