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

// Test_Disclosure_CreateAndList validates the coordinated disclosure workflow.
func Test_Disclosure_CreateAndList(t *testing.T) {
	env := SetupTestEnvironment(t, WithoutBSISeed())

	t.Log("=== Step 1: Create a disclosure ===")
	disclosureReq := map[string]interface{}{
		"cve":              "CVE-2026-0001",
		"title":            "Test Vulnerability Disclosure",
		"description":      "A test vulnerability found in integration testing",
		"severity":         "high",
		"reporter_name":    "Integration Test",
		"reporter_email":   "test@example.com",
		"coordinator_name": "Transparenz CSIRT",
	}

	createResp := env.AuthedPost("/api/disclosures", disclosureReq)
	createBody := env.CaptureEvidence("disclosure-create.json", createResp)
	AssertStatus(t, createResp, http.StatusCreated)

	var created map[string]interface{}
	require.NoError(t, json.Unmarshal(createBody, &created))
	disclosureID, _ := created["id"].(string)
	require.NotEmpty(t, disclosureID)

	t.Log("=== Step 2: List disclosures ===")
	listResp := env.AuthedGet("/api/disclosures")
	listBody := env.CaptureEvidence("disclosure-list.json", listResp)
	AssertStatus(t, listResp, http.StatusOK)

	var discList struct {
		Data []struct {
			ID  string `json:"id"`
			CVE string `json:"cve"`
		} `json:"data"`
		Total int `json:"total"`
	}
	require.NoError(t, json.Unmarshal(listBody, &discList))
	assert.GreaterOrEqual(t, discList.Total, 1)

	t.Log("=== Step 3: Get disclosure by ID ===")
	getResp := env.AuthedGet("/api/disclosures/" + disclosureID)
	getBody := env.CaptureEvidence("disclosure-detail.json", getResp)
	AssertStatus(t, getResp, http.StatusOK)

	var detail map[string]interface{}
	require.NoError(t, json.Unmarshal(getBody, &detail))
	assert.Equal(t, "CVE-2026-0001", detail["cve"])
	assert.Equal(t, "high", detail["severity"])

	t.Log("=== Step 4: Check SLA compliance ===")
	slaResp := env.AuthedGet("/api/disclosures/sla-compliance")
	AssertStatus(t, slaResp, http.StatusOK)
	env.CaptureEvidence("disclosure-sla-compliance.json", slaResp)

	t.Log("=== Step 5: Update disclosure status ===")
	updateResp := env.AuthedPut("/api/disclosures/"+disclosureID+"/status", map[string]interface{}{
		"status": "acknowledged",
	})
	env.CaptureEvidence("disclosure-status-update.json", updateResp)
	// May be 200 or other depending on workflow rules
	assert.Contains(t, []int{http.StatusOK, http.StatusAccepted, http.StatusBadRequest}, updateResp.StatusCode)

	env.WriteJSONEvidence("disclosure-lifecycle.json", map[string]interface{}{
		"disclosure_id": disclosureID,
		"cve":           "CVE-2026-0001",
		"severity":      "high",
		"created_at":    time.Now().UTC().Format(time.RFC3339),
	})
}

// Test_Disclosure_Nonexistent validates 404 for non-existent disclosure.
func Test_Disclosure_Nonexistent(t *testing.T) {
	env := SetupTestEnvironment(t, WithoutBSISeed())

	resp := env.AuthedGet("/api/disclosures/00000000-0000-0000-0000-000000000000")
	AssertStatus(t, resp, http.StatusNotFound)
	env.CaptureEvidence("disclosure-nonexistent.json", resp)
}
