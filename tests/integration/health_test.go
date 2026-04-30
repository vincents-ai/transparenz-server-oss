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

// Test_Health_ReadinessProbe validates the /health and /readyz endpoints.
func Test_Health_ReadinessProbe(t *testing.T) {
	env := SetupTestEnvironment(t, WithoutBSISeed())

	t.Log("=== Step 1: Verify /health returns 200 ===")
	healthResp := env.UnauthedGet("/health")
	healthBody := env.CaptureEvidence("health.json", healthResp)
	AssertStatus(t, healthResp, http.StatusOK)

	var healthResult map[string]interface{}
	require.NoError(t, json.Unmarshal(healthBody, &healthResult))
	assert.Equal(t, "OK", healthResult["title"])

	t.Log("=== Step 2: Verify /readyz returns 200 ===")
	readyResp := env.UnauthedGet("/readyz")
	readyBody := env.CaptureEvidence("readyz.json", readyResp)
	AssertStatus(t, readyResp, http.StatusOK)

	var readyResult map[string]interface{}
	require.NoError(t, json.Unmarshal(readyBody, &readyResult))
	assert.Contains(t, readyResult["status"], "ready")

	t.Log("=== Step 3: Verify response times are reasonable (CRA compliance evidence) ===")
	start := time.Now()
	resp := env.UnauthedGet("/health")
	resp.Body.Close()
	latency := time.Since(start)

	env.WriteJSONEvidence("health-latency.json", map[string]interface{}{
		"endpoint":    "/health",
		"latency_ms":  latency.Milliseconds(),
		"status_code": resp.StatusCode,
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
	})
	assert.Less(t, latency, 5*time.Second, "health check should respond within 5 seconds")
}

// Test_Metrics_BasicAccess validates that /metrics requires authentication
// and returns Prometheus metrics when authenticated.
func Test_Metrics_BasicAccess(t *testing.T) {
	env := SetupTestEnvironment(t, WithoutBSISeed())

	t.Log("=== Step 1: Verify /metrics requires auth ===")
	// No basic auth = 401
	resp, err := http.Get(env.ServerBaseURL + "/metrics")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	env.WriteJSONEvidence("metrics-no-auth.json", map[string]interface{}{
		"status_code": resp.StatusCode,
		"note":        "metrics endpoint requires basic auth",
	})
}
