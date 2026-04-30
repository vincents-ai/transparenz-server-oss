// Copyright (c) 2026 Vincent Palmer. All rights reserved.
package bdd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/cucumber/godog"
	"github.com/google/uuid"
	"github.com/transparenz/transparenz-server-oss/internal/models"
)

func RegisterAnalystWorkflowSteps(s *godog.ScenarioContext) {
	// Vulnerability with CVSS
	s.Step(`^the vulnerability "([^"]*)" has a CVSS score of ([\d.]+)$`, analystSetCVSS)

	// List with GRC
	s.Step(`^I list vulnerabilities with GRC mappings$`, analystListVulnsWithGRC)

	// Support period management
	s.Step(`^I update the organization support period to (\d+) months$`, adminUpdateSupportPeriod)
	s.Step(`^I update the organization support period to 0 months$`, adminUpdateSupportPeriodZero)
	s.Step(`^I update the organization support period as a regular user$`, adminUpdateSupportPeriodAsUser)
	s.Step(`^I get the organization support period$`, adminGetSupportPeriod)

	// Telemetry configuration
	// Note: "I create a telemetry config with OTel endpoint" is already registered in security_steps.go
	s.Step(`^I get the telemetry configuration$`, adminGetTelemetryConfig)
	s.Step(`^telemetry is configured with a valid metrics token$`, adminSeedTelemetryConfig)
	s.Step(`^I rotate the telemetry metrics token$`, adminRotateTelemetryToken)
	s.Step(`^I create a telemetry config with provider "([^"]*)"$`, adminCreateTelemetryBadProvider)

	// Disclosure lifecycle steps
	s.Step(`^I update the last disclosure status to "([^"]*)" with fix version "([^"]*)"$`, disclosureUpdateStatusWithFix)
	s.Step(`^I update the last disclosure status to "([^"]*)" with notes "([^"]*)"$`, disclosureUpdateStatusWithNotes)

	// Compliance event seeding is already registered in lifecycle_steps.go
}

// --- Security Analyst: Vulnerability CVSS ---

func analystSetCVSS(cve string, cvss float64) error {
	orgID := uuid.MustParse(tc().OrgID)
	return tc().DB.Model(&models.Vulnerability{}).
		Where("org_id = ? AND cve = ?", orgID, cve).
		Update("cvss_score", cvss).Error
}

// --- Security Analyst: List with GRC ---

func analystListVulnsWithGRC() error {
	req := httptest.NewRequest(http.MethodGet, "/api/vulnerabilities?include_grc=true", nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

// --- Admin: Support Period ---

func adminUpdateSupportPeriod(months int) error {
	return adminUpdateSupportPeriodTo(months)
}

func adminUpdateSupportPeriodZero() error {
	return adminUpdateSupportPeriodTo(0)
}

func adminUpdateSupportPeriodTo(months int) error {
	body := fmt.Sprintf(`{"months":%d}`, months)
	req := httptest.NewRequest(http.MethodPut, "/api/orgs/support-period", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	req.Header.Set("Content-Type", "application/json")
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func adminUpdateSupportPeriodAsUser() error {
	body := `{"months":12}`
	req := httptest.NewRequest(http.MethodPut, "/api/orgs/support-period", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.UserToken)
	req.Header.Set("Content-Type", "application/json")
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func adminGetSupportPeriod() error {
	req := httptest.NewRequest(http.MethodGet, "/api/orgs/support-period", nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

// --- Admin: Telemetry ---

func adminGetTelemetryConfig() error {
	req := httptest.NewRequest(http.MethodGet, "/api/telemetry/config", nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func adminSeedTelemetryConfig() error {
	orgID := uuid.MustParse(tc().OrgID)
	config := models.OrgTelemetryConfig{
		OrgID:     orgID,
		Provider:  "prometheus",
		Active:    true,
	}
	return tc().DB.Create(&config).Error
}

func adminRotateTelemetryToken() error {
	req := httptest.NewRequest(http.MethodPost, "/api/telemetry/config/rotate-token", nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func adminCreateTelemetryBadProvider(provider string) error {
	body := fmt.Sprintf(`{"provider":"%s","metrics_token":"test-token"}`, provider)
	req := httptest.NewRequest(http.MethodPost, "/api/telemetry/config", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	req.Header.Set("Content-Type", "application/json")
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

// --- Disclosure Lifecycle Extensions ---

func disclosureUpdateStatusWithFix(status, fixVersion string) error {
	body := fmt.Sprintf(`{"status":"%s","fix_version":"%s"}`, status, fixVersion)
	req := httptest.NewRequest(http.MethodPut, "/api/disclosures/"+lastDisclosureID+"/status", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	req.Header.Set("Content-Type", "application/json")
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func disclosureUpdateStatusWithNotes(status, notes string) error {
	body := fmt.Sprintf(`{"status":"%s","internal_notes":"%s"}`, status, notes)
	req := httptest.NewRequest(http.MethodPut, "/api/disclosures/"+lastDisclosureID+"/status", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	req.Header.Set("Content-Type", "application/json")
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

// Ensure json import is used
var _ = json.Marshal
