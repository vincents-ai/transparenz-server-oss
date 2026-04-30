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

// Test_Compliance_Status validates the compliance status endpoint.
func Test_Compliance_Status(t *testing.T) {
	env := SetupTestEnvironment(t, WithoutBSISeed())

	resp := env.AuthedGet("/api/compliance/status")
	body := env.CaptureEvidence("compliance-status.json", resp)
	AssertStatus(t, resp, http.StatusOK)

	var status map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &status))

	// Verify compliance_score is in valid range
	if score, ok := status["compliance_score"].(float64); ok {
		assert.GreaterOrEqual(t, score, float64(0))
		assert.LessOrEqual(t, score, float64(100))
	}

	env.WriteJSONEvidence("compliance-status-validated.json", map[string]interface{}{
		"has_compliance_score":   status["compliance_score"] != nil,
		"has_total_vulnerabilities": status["total_vulnerabilities"] != nil,
	})
}

// Test_Compliance_SLA_Tracking validates the SLA tracking endpoint.
func Test_Compliance_SLA_Tracking(t *testing.T) {
	env := SetupTestEnvironment(t, WithoutBSISeed())

	resp := env.AuthedGet("/api/compliance/sla")
	body := env.CaptureEvidence("compliance-sla.json", resp)
	AssertStatus(t, resp, http.StatusOK)

	var slaList struct {
		Data []interface{} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(body, &slaList))

	env.WriteJSONEvidence("compliance-sla-summary.json", map[string]interface{}{
		"sla_entries": len(slaList.Data),
	})
}

// Test_Compliance_ReportExploited validates the exploited vulnerability reporting endpoint.
func Test_Compliance_ReportExploited(t *testing.T) {
	env := SetupTestEnvironment(t, WithoutBSISeed())

	// Upload a vulnerable SBOM first to create a vulnerability
	sbomData := GenerateCycloneDXWithSpecificCVEs(t)
	upload := env.UploadSBOM("exploited.cdx", sbomData)
	scan := env.CreateScan(upload.ID)
	env.WaitForScanCompletion(scan.ScanID, 120*time.Second)

	// List vulnerabilities to find one
	listResp := env.AuthedGet("/api/vulnerabilities")
	var vulnList struct {
		Data []struct {
			CVE string `json:"cve"`
		} `json:"data"`
	}
	DecodeResponse(t, listResp, &vulnList)

	if len(vulnList.Data) > 0 {
		t.Logf("=== Reporting CVE %s as exploited ===", vulnList.Data[0].CVE)
		reportResp := env.AuthedPost("/api/compliance/exploited", map[string]interface{}{
			"cve": vulnList.Data[0].CVE,
		})
		body := env.CaptureEvidence("exploited-report.json", reportResp)
		// May be 200 or 403 depending on role
		if reportResp.StatusCode == http.StatusOK {
			var result map[string]interface{}
			require.NoError(t, json.Unmarshal(body, &result))
		} else {
			t.Logf("Report exploited returned %d (may need compliance_officer role)", reportResp.StatusCode)
		}
	} else {
		t.Log("No vulnerabilities found to report as exploited")
	}
}
