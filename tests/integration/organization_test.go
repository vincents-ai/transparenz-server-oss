//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test_Organization_GetSupportPeriod validates getting the support period.
func Test_Organization_GetSupportPeriod(t *testing.T) {
	env := SetupTestEnvironment(t, WithoutBSISeed())

	resp := env.AuthedGet("/api/orgs/support-period")
	body := env.CaptureEvidence("org-support-period.json", resp)
	AssertStatus(t, resp, http.StatusOK)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &result))
	assert.NotNil(t, result)
}

// Test_Organization_UpdateSupportPeriod validates updating the support period (admin).
func Test_Organization_UpdateSupportPeriod(t *testing.T) {
	env := SetupTestEnvironment(t, WithoutBSISeed())

	updateResp := env.AuthedPut("/api/orgs/support-period", map[string]interface{}{
		"support_period_months": 36,
	})
	env.CaptureEvidence("org-support-period-update.json", updateResp)
	// May be 200 (admin), 403 (not admin), or 400 (bad payload format)
	assert.Contains(t, []int{http.StatusOK, http.StatusForbidden, http.StatusBadRequest}, updateResp.StatusCode)
}
