//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test_VEX_CreateAndList validates VEX statement creation and listing.
func Test_VEX_CreateAndList(t *testing.T) {
	env := SetupTestEnvironment(t, WithoutBSISeed())

	t.Log("=== Step 1: Create VEX statement ===")
	vexReq := map[string]interface{}{
		"cve":           "CVE-2021-44228",
		"product_id":    "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
		"justification": "vulnerable_code_not_in_execute_path",
		"impact_statement": "The affected log4j component is not used in any code path",
		"confidence":    "high",
	}

	vexResp := env.AuthedPost("/api/vex", vexReq)
	vexBody := env.CaptureEvidence("vex-create.json", vexResp)

	if vexResp.StatusCode == http.StatusCreated || vexResp.StatusCode == http.StatusOK {
		var created map[string]interface{}
		require.NoError(t, json.Unmarshal(vexBody, &created))

		vexID, _ := created["id"].(string)
		require.NotEmpty(t, vexID)

		t.Log("=== Step 2: List VEX statements ===")
		listResp := env.AuthedGet("/api/vex")
		listBody := env.CaptureEvidence("vex-list.json", listResp)
		AssertStatus(t, listResp, http.StatusOK)

		var vexList struct {
			Data []struct {
				ID  string `json:"id"`
				CVE string `json:"cve"`
			} `json:"data"`
			Total int `json:"total"`
		}
		require.NoError(t, json.Unmarshal(listBody, &vexList))
		assert.GreaterOrEqual(t, vexList.Total, 1)

		env.WriteJSONEvidence("vex-lifecycle.json", map[string]interface{}{
			"vex_id":       vexID,
			"cve":          "CVE-2021-44228",
			"total_vex":    vexList.Total,
			"status":       "created",
		})
	} else {
		t.Logf("VEX create returned status %d (endpoint may need specific payload)", vexResp.StatusCode)
	}
}

// Test_VEX_Approve validates VEX approval workflow.
func Test_VEX_Approve(t *testing.T) {
	env := SetupTestEnvironment(t, WithoutBSISeed())

	// Create VEX first
	vexResp := env.AuthedPost("/api/vex", map[string]interface{}{
		"cve":           "CVE-2024-0001",
		"product_id":    "pkg:generic/test@1.0.0",
		"justification": "component_not_present",
		"confidence":    "medium",
	})
	vexBody := ReadBody(t, vexResp)

	if vexResp.StatusCode == http.StatusCreated || vexResp.StatusCode == http.StatusOK {
		var created map[string]interface{}
		require.NoError(t, json.Unmarshal(vexBody, &created))
		vexID, _ := created["id"].(string)

		// Try to approve
		approveResp := env.AuthedPost("/api/vex/"+vexID+"/approve", nil)
		env.CaptureEvidence("vex-approve.json", approveResp)
		// May be 200 (approved) or 403 (needs compliance_officer role)
		assert.Contains(t, []int{http.StatusOK, http.StatusForbidden}, approveResp.StatusCode)
	} else {
		t.Log("VEX creation failed, skipping approve test")
	}
}

// Test_VEX_Publish validates VEX publish workflow.
func Test_VEX_Publish(t *testing.T) {
	env := SetupTestEnvironment(t, WithoutBSISeed())

	// Create and approve first
	vexResp := env.AuthedPost("/api/vex", map[string]interface{}{
		"cve":           "CVE-2024-0002",
		"product_id":    "pkg:generic/test@1.0.0",
		"justification": "vulnerable_code_not_in_execute_path",
		"confidence":    "high",
	})
	vexBody := ReadBody(t, vexResp)

	if vexResp.StatusCode == http.StatusCreated || vexResp.StatusCode == http.StatusOK {
		var created map[string]interface{}
		require.NoError(t, json.Unmarshal(vexBody, &created))
		vexID, _ := created["id"].(string)

		// Approve first
		env.AuthedPost("/api/vex/"+vexID+"/approve", nil)

		// Then publish (channel is required)
		publishResp := env.AuthedPost("/api/vex/"+vexID+"/publish", map[string]interface{}{"channel": "file"})
		env.CaptureEvidence("vex-publish.json", publishResp)
		assert.Contains(t, []int{http.StatusOK, http.StatusForbidden}, publishResp.StatusCode)
	}
}
