// Copyright (c) 2026 Vincent Palmer. Licensed under AGPL-3.0.
package bdd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/google/uuid"
	"github.com/transparenz/transparenz-server-oss/internal/models"
)

func RegisterExtendedSteps(s *godog.ScenarioContext) {
	// Compliance event seeding (simplified for OSS — no signing)
	s.Step(`^a compliance event of type "([^"]*)" with severity "([^"]*)" exists$`, extSeedComplianceEvent)

	// Export with date range
	s.Step(`^I export the audit trail from "([^"]*)" to "([^"]*)" as CSV$`, extExportCSVDateRange)
	s.Step(`^I export the audit trail as CSV with role "([^"]*)"$`, extExportCSVWithRole)
	s.Step(`^the CSV should contain a header row$`, extAssertCSVHeader)

	// ENISA lifecycle (read-only in OSS)
	s.Step(`^I get ENISA submission with ID "([^"]*)"$`, extGetEnisaByID)
	s.Step(`^the response should contain 0 ENISA submissions$`, extAssertZeroEnisaSubmissions)

	// Edge cases: SBOM deletion by ID
	s.Step(`^I delete SBOM with ID "([^"]*)"$`, extDeleteSBOMByID)

	// Edge cases: pagination
	s.Step(`^I list scans with limit (\d+)$`, extListScansWithLimit)
	s.Step(`^I list VEX statements with limit (\d+)$`, extListVEXWithLimit)

	// Edge cases: VEX empty body
	s.Step(`^I create a VEX statement with empty body$`, extVEXEmptyBody)

	// Edge cases: sovereign feed source
	s.Step(`^the vulnerability "([^"]*)" has sovereign feed source "([^"]*)"$`, extSetSovereignFeedSource)

	// Support period management
	s.Step(`^I update the organization support period to (\d+) months$`, extUpdateSupportPeriod)
	s.Step(`^I update the organization support period as a regular user$`, extUpdateSupportPeriodAsUser)
	s.Step(`^I update the organization support period to 0 months$`, extUpdateSupportPeriodZero)
	s.Step(`^I get the organization support period$`, extGetSupportPeriod)
	s.Step(`^I export the enriched SBOM with ID "([^"]*)"$`, extExportEnrichedSBOM)
	s.Step(`^a GRC mapping exists for the organization$`, extSeedGRCMapping)
}

// --- Compliance Event Seeding ---

func extSeedComplianceEvent(eventType, severity string) error {
	orgID := uuid.MustParse(tc().OrgID)
	event := models.ComplianceEvent{
		ID:        uuid.New(),
		OrgID:     orgID,
		EventType: eventType,
		Severity:  severity,
		Cve:       "CVE-2024-EVENT",
		Timestamp: time.Now(),
		Metadata:  models.JSONMap{"source": "bdd-test"},
	}
	return tc().DB.Create(&event).Error
}

// --- Export with Date Range ---

func extExportCSVDateRange(start, end string) error {
	url := fmt.Sprintf("/api/export/audit?format=csv&start=%s&end=%s", start, end)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.ComplianceOfficerToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func extExportCSVWithRole(role string) error {
	var token string
	switch role {
	case "compliance_officer":
		token = tc().Tokens.ComplianceOfficerToken
	case "admin":
		token = tc().Tokens.AdminToken
	default:
		token = tc().Tokens.UserToken
	}
	req := httptest.NewRequest(http.MethodGet, "/api/export/audit?format=csv", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func extAssertCSVHeader() error {
	if lastResponse == nil {
		return fmt.Errorf("no response recorded")
	}
	body := lastResponse.Body.String()
	if !strings.Contains(body, "Timestamp") || !strings.Contains(body, "Event Type") {
		return fmt.Errorf("CSV missing header row: %s", body[:min(len(body), 200)])
	}
	return nil
}

// --- ENISA Lifecycle ---

func extGetEnisaByID(id string) error {
	req := httptest.NewRequest(http.MethodGet, "/api/enisa/submissions/"+id, nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func extAssertZeroEnisaSubmissions() error {
	if lastResponse == nil {
		return fmt.Errorf("no response recorded")
	}
	var body struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal(lastResponse.Body.Bytes(), &body); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	if body.Count != 0 {
		return fmt.Errorf("expected 0 ENISA submissions, got %d", body.Count)
	}
	return nil
}

// --- Edge Cases: SBOM Deletion ---

func extDeleteSBOMByID(id string) error {
	req := httptest.NewRequest(http.MethodDelete, "/api/sboms/"+id, nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

// --- Edge Cases: Pagination ---

func extListScansWithLimit(limit int) error {
	url := fmt.Sprintf("/api/scans?limit=%d", limit)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func extListVEXWithLimit(limit int) error {
	url := fmt.Sprintf("/api/vex?limit=%d", limit)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

// --- Edge Cases: VEX Empty Body ---

func extVEXEmptyBody() error {
	req := httptest.NewRequest(http.MethodPost, "/api/vex", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	req.Header.Set("Content-Type", "application/json")
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

// --- Edge Cases: Sovereign Feed Source ---

func extSetSovereignFeedSource(cve, source string) error {
	orgID := uuid.MustParse(tc().OrgID)
	return tc().DB.Model(&models.Vulnerability{}).
		Where("org_id = ? AND cve = ?", orgID, cve).
		Update("sovereign_feed_source", source).Error
}

// --- Support Period Management ---

func extUpdateSupportPeriod(months int) error {
	body := fmt.Sprintf(`{"months":%d}`, months)
	req := httptest.NewRequest(http.MethodPut, "/api/orgs/support-period", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	req.Header.Set("Content-Type", "application/json")
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func extUpdateSupportPeriodAsUser() error {
	body := `{"months":12}`
	req := httptest.NewRequest(http.MethodPut, "/api/orgs/support-period", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.UserToken)
	req.Header.Set("Content-Type", "application/json")
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func extUpdateSupportPeriodZero() error {
	return extUpdateSupportPeriod(0)
}

func extGetSupportPeriod() error {
	req := httptest.NewRequest(http.MethodGet, "/api/orgs/support-period", nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

// --- Enriched SBOM Export ---

func extExportEnrichedSBOM(id string) error {
	url := fmt.Sprintf("/api/export/enriched-sbom/%s", id)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.ComplianceOfficerToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func extSeedGRCMapping() error {
	orgID := uuid.MustParse(tc().OrgID)
	mapping := models.GRCMapping{
		ID:          uuid.New(),
		OrgID:       orgID,
		Framework:   "BSI IT-Grundschutz",
		ControlID:   "APP.4.4.A11",
		MappingType: "direct",
		Confidence:  0.95,
		Evidence:    "SBOM vulnerability scan coverage",
	}
	return tc().DB.Create(&mapping).Error
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
