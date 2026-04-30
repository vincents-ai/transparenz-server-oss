//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test_SBOM_UploadDownloadLifecycle validates the complete SBOM CRUD lifecycle:
// upload → list → get by ID → download → delete → verify deletion.
// Each step produces audit evidence.
func Test_SBOM_UploadDownloadLifecycle(t *testing.T) {
	env := SetupTestEnvironment(t, WithoutBSISeed())

	t.Log("=== Step 1: Upload a CycloneDX SBOM ===")
	sbomData := GenerateMultiComponentCycloneDXSBOM(t)
	env.WriteEvidence("input-multicomponent.cdx.json", sbomData)

	uploadResp := env.UploadSBOM("multicomponent.cdx", sbomData)
	require.NotEmpty(t, uploadResp.ID)
	assert.Equal(t, "multicomponent.cdx", uploadResp.Filename)
	assert.Equal(t, "cyclonedx-json", uploadResp.Format)
	assert.NotEmpty(t, uploadResp.SHA256)

	t.Log("=== Step 2: List SBOMs — verify it appears ===")
	listResp := env.ListSBOMs()
	env.WriteJSONEvidence("sbom-list-after-upload.json", listResp)
	require.Equal(t, 1, listResp.Total)
	assert.Equal(t, uploadResp.ID, listResp.Data[0].ID)

	t.Log("=== Step 3: Get SBOM by ID ===")
	getResp := env.AuthedGet("/api/sboms/" + uploadResp.ID)
	getBody := env.CaptureEvidence("sbom-get-"+uploadResp.ID+".json", getResp)
	AssertStatus(t, getResp, http.StatusOK)

	var sbomDetail map[string]interface{}
	require.NoError(t, json.Unmarshal(getBody, &sbomDetail))
	assert.Equal(t, uploadResp.ID, sbomDetail["id"])
	assert.Equal(t, "multicomponent.cdx", sbomDetail["filename"])

	t.Log("=== Step 4: Download SBOM ===")
	downloaded := env.DownloadSBOM(uploadResp.ID)
	require.NotEmpty(t, downloaded)

	// Verify downloaded SBOM is valid JSON with expected structure
	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(downloaded, &parsed))
	assert.Equal(t, "CycloneDX", parsed["bomFormat"])
	assert.Equal(t, "1.5", parsed["specVersion"])

	t.Log("=== Step 5: Delete SBOM ===")
	env.DeleteSBOM(uploadResp.ID)

	t.Log("=== Step 6: Verify deletion — list should be empty ===")
	listAfterDelete := env.ListSBOMs()
	env.WriteJSONEvidence("sbom-list-after-delete.json", listAfterDelete)
	assert.Equal(t, 0, listAfterDelete.Total)

	t.Log("=== Step 7: Verify deletion — get by ID returns 404 ===")
	getDeleted := env.AuthedGet("/api/sboms/" + uploadResp.ID)
	AssertStatus(t, getDeleted, http.StatusNotFound)

	env.WriteJSONEvidence("lifecycle-evidence.json", map[string]interface{}{
		"sbom_id":    uploadResp.ID,
		"filename":   uploadResp.Filename,
		"format":     uploadResp.Format,
		"sha256":     uploadResp.SHA256,
		"operations": []string{"upload", "list", "get", "download", "delete", "verify_404"},
	})
}

// Test_SBOM_UploadMultiple verifies uploading multiple SBOMs and listing with pagination.
func Test_SBOM_UploadMultiple(t *testing.T) {
	env := SetupTestEnvironment(t, WithoutBSISeed())

	// Upload 3 SBOMs with unique content
	ids := make([]string, 3)
	for i := 0; i < 3; i++ {
		sbomData := GenerateLargeCycloneDXSBOM(t, 5+i) // different sizes = different content
		resp := env.UploadSBOM(fmt.Sprintf("app-%d.cdx", i), sbomData)
		ids[i] = resp.ID
	}

	// List all
	listResp := env.ListSBOMs()
	env.WriteJSONEvidence("multi-upload-list.json", listResp)
	assert.Equal(t, 3, listResp.Total)

	// List with limit
	limitedResp := env.AuthedGet("/api/sboms?limit=1&offset=0")
	var limited listSBOMsResponse
	DecodeResponse(t, limitedResp, &limited)
	env.WriteJSONEvidence("multi-upload-list-limited.json", limited)
	assert.Equal(t, 1, limited.Count)
	assert.Equal(t, 3, limited.Total)
}

// Test_SBOM_UploadDuplicateFilename verifies that uploading two SBOMs with the same filename works (different IDs).
func Test_SBOM_UploadDuplicateFilename(t *testing.T) {
	env := SetupTestEnvironment(t, WithoutBSISeed())

	sbom1 := GenerateSafeCycloneDXSBOM(t)
	sbom2 := GenerateVulnerableCycloneDXSBOM(t)

	upload1 := env.UploadSBOM("duplicate.cdx", sbom1)
	upload2 := env.UploadSBOM("duplicate.cdx", sbom2)

	assert.NotEqual(t, upload1.ID, upload2.ID, "different uploads should get different IDs")
	assert.Equal(t, upload1.Filename, upload2.Filename)

	listResp := env.ListSBOMs()
	assert.Equal(t, 2, listResp.Total)
}

// Test_SBOM_GetNonexistent verifies 404 for a non-existent SBOM.
func Test_SBOM_GetNonexistent(t *testing.T) {
	env := SetupTestEnvironment(t, WithoutBSISeed())

	resp := env.AuthedGet("/api/sboms/00000000-0000-0000-0000-000000000000")
	AssertStatus(t, resp, http.StatusNotFound)
	env.CaptureEvidence("get-nonexistent.json", resp)
}

// Test_SBOM_DownloadNonexistent verifies 404 for downloading a non-existent SBOM.
func Test_SBOM_DownloadNonexistent(t *testing.T) {
	env := SetupTestEnvironment(t, WithoutBSISeed())

	resp := env.AuthedGet("/api/sboms/00000000-0000-0000-0000-000000000000/download")
	AssertStatus(t, resp, http.StatusNotFound)
	env.CaptureEvidence("download-nonexistent.json", resp)
}

// Test_SBOM_DeleteNonexistent verifies 404 for deleting a non-existent SBOM.
func Test_SBOM_DeleteNonexistent(t *testing.T) {
	env := SetupTestEnvironment(t, WithoutBSISeed())

	resp := env.AuthedDelete("/api/sboms/00000000-0000-0000-0000-000000000000")
	AssertStatus(t, resp, http.StatusNotFound)
	env.CaptureEvidence("delete-nonexistent.json", resp)
}

// Test_SBOM_EmptyComponents verifies uploading a valid SBOM with zero components.
func Test_SBOM_EmptyComponents(t *testing.T) {
	env := SetupTestEnvironment(t, WithoutBSISeed())

	sbomData := GenerateEmptyCycloneDXSBOM(t)
	env.WriteEvidence("empty-sbom.cdx.json", sbomData)

	uploadResp := env.UploadSBOM("empty.cdx", sbomData)
	require.NotEmpty(t, uploadResp.ID)

	// Download and verify it round-trips correctly
	downloaded := env.DownloadSBOM(uploadResp.ID)
	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(downloaded, &parsed))
	components, ok := parsed["components"].([]interface{})
	require.True(t, ok, "components should be an array")
	assert.Equal(t, 0, len(components))
}
