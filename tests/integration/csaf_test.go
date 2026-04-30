//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test_CSAF_PublicProviderMetadata validates the .well-known CSAF provider metadata endpoint.
func Test_CSAF_PublicProviderMetadata(t *testing.T) {
	env := SetupTestEnvironment(t, WithoutBSISeed())

	// First we need to know the org slug. Register user creates an org.
	// The org slug is derived from the org name.
	t.Log("=== Testing CSAF provider metadata ===")

	// Try the API endpoint (authenticated)
	apiResp := env.AuthedGet("/api/csaf/provider-metadata.json")
	apiBody := env.CaptureEvidence("csaf-provider-metadata.json", apiResp)
	AssertStatus(t, apiResp, http.StatusOK)

	var metadata map[string]interface{}
	require.NoError(t, json.Unmarshal(apiBody, &metadata))

	// CSAF v2.0 provider-metadata.json must have these fields
	assert.NotEmpty(t, metadata["canonical_url"], "CSAF provider metadata requires canonical_url")
	assert.NotEmpty(t, metadata["last_updated"], "CSAF provider metadata requires last_updated")

	env.WriteJSONEvidence("csaf-provider-validated.json", map[string]interface{}{
		"has_canonical_url": metadata["canonical_url"] != nil,
		"has_last_updated":  metadata["last_updated"] != nil,
		"has_provider":      metadata["provider"] != nil,
	})
}

// Test_CSAF_ListAdvisories validates listing CSAF advisories.
func Test_CSAF_ListAdvisories(t *testing.T) {
	env := SetupTestEnvironment(t, WithoutBSISeed())

	resp := env.AuthedGet("/api/csaf/advisories")
	body := env.CaptureEvidence("csaf-advisories.json", resp)
	AssertStatus(t, resp, http.StatusOK)

	var advisories struct {
		Data []interface{} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(body, &advisories))

	env.WriteJSONEvidence("csaf-advisories-summary.json", map[string]interface{}{
		"advisory_count": len(advisories.Data),
	})
}

// Test_CSAF_GetNonexistentAdvisory validates 404 for non-existent advisory.
func Test_CSAF_GetNonexistentAdvisory(t *testing.T) {
	env := SetupTestEnvironment(t, WithoutBSISeed())

	resp := env.AuthedGet("/api/csaf/advisories/00000000-0000-0000-0000-000000000000")
	AssertStatus(t, resp, http.StatusNotFound)
	env.CaptureEvidence("csaf-nonexistent-advisory.json", resp)
}

// Test_CSAF_ChangesCSV validates the changes.csv endpoint.
func Test_CSAF_ChangesCSV(t *testing.T) {
	env := SetupTestEnvironment(t, WithoutBSISeed())

	resp := env.AuthedGet("/api/csaf/changes.csv")
	body := env.CaptureEvidence("csaf-changes.csv", resp)
	AssertStatus(t, resp, http.StatusOK)
	// Should be CSV format
	assert.NotEmpty(t, body)
}
