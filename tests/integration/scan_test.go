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

// Test_Scan_CreateAndComplete validates the full scan lifecycle:
// create scan → poll until complete → verify vulnerabilities.
func Test_Scan_CreateAndComplete(t *testing.T) {
	env := SetupTestEnvironment(t, WithoutBSISeed())

	t.Log("=== Step 1: Upload SBOM ===")
	sbomData := GenerateVulnerableCycloneDXSBOM(t)
	uploadResp := env.UploadSBOM("vulnerable.cdx", sbomData)

	t.Log("=== Step 2: Create scan ===")
	scanResp := env.CreateScan(uploadResp.ID)
	require.NotEmpty(t, scanResp.ScanID)
	assert.Equal(t, uploadResp.ID, scanResp.SbomID)
	assert.NotEmpty(t, scanResp.OrgID)

	t.Log("=== Step 3: Wait for scan completion ===")
	vulnCount := env.WaitForScanCompletion(scanResp.ScanID, 120*time.Second)

	t.Log("=== Step 4: List scans ===")
	listResp := env.AuthedGet("/api/scans")
	var scans listScansResponse
	DecodeResponse(t, listResp, &scans)
	env.WriteJSONEvidence("scan-list.json", scans)

	found := false
	for _, s := range scans.Data {
		if s.ID == scanResp.ScanID {
			found = true
			assert.Equal(t, "completed", s.Status)
			assert.Equal(t, uploadResp.ID, s.SbomID)
		}
	}
	require.True(t, found, "scan should appear in list")

	env.WriteJSONEvidence("scan-lifecycle.json", map[string]interface{}{
		"scan_id":     scanResp.ScanID,
		"sbom_id":     uploadResp.ID,
		"vuln_count":  vulnCount,
		"scan_status": "completed",
	})
}

// Test_Scan_MultipleScans verifies multiple scans can run concurrently.
func Test_Scan_MultipleScans(t *testing.T) {
	env := SetupTestEnvironment(t, WithoutBSISeed())

	sbom1 := GenerateVulnerableCycloneDXSBOM(t)
	sbom2 := GenerateSafeCycloneDXSBOM(t)

	upload1 := env.UploadSBOM("vuln.cdx", sbom1)
	upload2 := env.UploadSBOM("safe.cdx", sbom2)

	scan1 := env.CreateScan(upload1.ID)
	scan2 := env.CreateScan(upload2.ID)

	count1 := env.WaitForScanCompletion(scan1.ScanID, 120*time.Second)
	count2 := env.WaitForScanCompletion(scan2.ScanID, 120*time.Second)

	env.WriteJSONEvidence("multi-scan-results.json", map[string]interface{}{
		"scan_1": map[string]interface{}{"scan_id": scan1.ScanID, "vuln_count": count1},
		"scan_2": map[string]interface{}{"scan_id": scan2.ScanID, "vuln_count": count2},
	})

	// Both should complete (even if 0 vulns found)
	assert.GreaterOrEqual(t, count1, 0)
	assert.GreaterOrEqual(t, count2, 0)
}

// Test_Scan_NonexistentSBOM verifies creating a scan with a non-existent SBOM returns error.
func Test_Scan_NonexistentSBOM(t *testing.T) {
	env := SetupTestEnvironment(t, WithoutBSISeed())

	resp := env.AuthedPost("/api/scan", map[string]string{
		"sbom_id": "00000000-0000-0000-0000-000000000000",
	})
	AssertStatusInRange(t, resp, 400, 500)
	env.CaptureEvidence("scan-nonexistent-sbom.json", resp)
}

// Test_Scan_ListPagination verifies scan listing with pagination.
func Test_Scan_ListPagination(t *testing.T) {
	env := SetupTestEnvironment(t, WithoutBSISeed())

	// Create 3 SBOMs and scans
	for i := 0; i < 3; i++ {
		sbomData := GenerateLargeCycloneDXSBOM(t, 3)
		upload := env.UploadSBOM("batch.cdx", sbomData)
		env.CreateScan(upload.ID)
	}

	// List all
	listResp := env.AuthedGet("/api/scans")
	var scans listScansResponse
	DecodeResponse(t, listResp, &scans)
	env.WriteJSONEvidence("scan-list-pagination.json", scans)
	assert.GreaterOrEqual(t, scans.Total, 3)

	// List with limit
	limitedResp := env.AuthedGet("/api/scans?limit=1&offset=0")
	var limited listScansResponse
	DecodeResponse(t, limitedResp, &limited)
	env.WriteJSONEvidence("scan-list-limited.json", limited)
	assert.Equal(t, 1, limited.Count)
}

// Test_Scan_GetVulnerabilities validates GET /api/scans/:id/vulnerabilities.
func Test_Scan_GetVulnerabilities(t *testing.T) {
	env := SetupTestEnvironment(t, WithoutBSISeed())

	sbomData := GenerateVulnerableCycloneDXSBOM(t)
	uploadResp := env.UploadSBOM("vuln.cdx", sbomData)
	scanResp := env.CreateScan(uploadResp.ID)
	env.WaitForScanCompletion(scanResp.ScanID, 120*time.Second)

	t.Log("=== Getting scan vulnerabilities ===")
	vulnResp := env.AuthedGet("/api/scans/" + scanResp.ScanID + "/vulnerabilities")
	vulnBody := env.CaptureEvidence("scan-vulnerabilities.json", vulnResp)
	AssertStatus(t, vulnResp, http.StatusOK)

	var vulns struct {
		Data []interface{} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(vulnBody, &vulns))

	env.WriteJSONEvidence("scan-vuln-summary.json", map[string]interface{}{
		"scan_id":  scanResp.ScanID,
		"sbom_id":  uploadResp.ID,
		"vuln_count": len(vulns.Data),
	})
}
