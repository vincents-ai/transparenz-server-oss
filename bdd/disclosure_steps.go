// Copyright (c) 2026 Vincent Palmer. All rights reserved.
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
	"github.com/transparenz/transparenz-server-oss/bdd/testcontext"
	"github.com/transparenz/transparenz-server-oss/internal/models"
)

var lastDisclosureID string
var secondOrgTokens *testcontext.TestTokens

func RegisterDisclosureSteps(s *godog.ScenarioContext) {
	s.Step(`^I create a disclosure with CVE "([^"]*)" and title "([^"]*)"$`, disclosureCreate)
	s.Step(`^I list disclosures$`, disclosureList)
	s.Step(`^I get the last created disclosure by ID$`, disclosureGetByID)
	s.Step(`^the response field "([^"]*)" should equal "([^"]*)"$`, disclosureAssertFieldValue)
	s.Step(`^I update the last disclosure status to "([^"]*)"$`, disclosureUpdateStatus)
	s.Step(`^I update the last disclosure status to "([^"]*)" with coordinator "([^"]*)" and email "([^"]*)"$`, disclosureUpdateStatusWithCoordinator)
	s.Step(`^I check SLA compliance$`, disclosureCheckSLA)
	s.Step(`^the SLA violations count should be greater than (\d+)$`, disclosureAssertSLAViolations)
	s.Step(`^a disclosure exists that was received (\d+) days ago$`, disclosureSeedOldDisclosure)
	s.Step(`^a second organization exists$`, disclosureSeedSecondOrg)
	s.Step(`^I list disclosures for the second organization$`, disclosureListSecondOrg)
	// Unhappy-path steps
	s.Step(`^I create a disclosure with missing CVE field$`, disclosureCreateMissingCVE)
	s.Step(`^I get disclosure with ID "([^"]*)"$`, disclosureGetArbitraryByID)
	s.Step(`^I update disclosure "([^"]*)" status to "([^"]*)"$`, disclosureUpdateArbitraryStatus)
}

func disclosureCreate(cve, title string) error {
	body := fmt.Sprintf(`{"cve":"%s","title":"%s","description":"Test vulnerability","severity":"high"}`, cve, title)
	req := httptest.NewRequest(http.MethodPost, "/api/disclosures", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	req.Header.Set("Content-Type", "application/json")
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	if lastResponse.Code == http.StatusCreated {
		var resp struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(lastResponse.Body.Bytes(), &resp); err == nil {
			lastDisclosureID = resp.ID
		}
	}
	return nil
}

func disclosureList() error {
	req := httptest.NewRequest(http.MethodGet, "/api/disclosures", nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func disclosureGetByID() error {
	req := httptest.NewRequest(http.MethodGet, "/api/disclosures/"+lastDisclosureID, nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func disclosureAssertFieldValue(field, expected string) error {
	if lastResponse == nil {
		return fmt.Errorf("no response recorded")
	}
	var body map[string]interface{}
	if err := json.Unmarshal(lastResponse.Body.Bytes(), &body); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	val, ok := body[field]
	if !ok {
		return fmt.Errorf("response missing field %q: %s", field, lastResponse.Body.String())
	}
	strVal, ok := val.(string)
	if !ok {
		return fmt.Errorf("field %q is not a string: %v", field, val)
	}
	if strVal != expected {
		return fmt.Errorf("expected field %q to be %q, got %q", field, expected, strVal)
	}
	return nil
}

func disclosureUpdateStatus(status string) error {
	body := fmt.Sprintf(`{"status":"%s"}`, status)
	req := httptest.NewRequest(http.MethodPut, "/api/disclosures/"+lastDisclosureID+"/status", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	req.Header.Set("Content-Type", "application/json")
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func disclosureUpdateStatusWithCoordinator(status, name, email string) error {
	body := fmt.Sprintf(`{"status":"%s","coordinator_name":"%s","coordinator_email":"%s"}`, status, name, email)
	req := httptest.NewRequest(http.MethodPut, "/api/disclosures/"+lastDisclosureID+"/status", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	req.Header.Set("Content-Type", "application/json")
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func disclosureCheckSLA() error {
	req := httptest.NewRequest(http.MethodGet, "/api/disclosures/sla-compliance", nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func disclosureAssertSLAViolations(min int) error {
	if lastResponse == nil {
		return fmt.Errorf("no response recorded")
	}
	var resp struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal(lastResponse.Body.Bytes(), &resp); err != nil {
		return fmt.Errorf("failed to parse SLA response: %w", err)
	}
	if resp.Count <= min {
		return fmt.Errorf("expected more than %d SLA violations, got %d", min, resp.Count)
	}
	return nil
}

func disclosureSeedOldDisclosure(daysAgo int) error {
	receivedAt := time.Now().AddDate(0, 0, -daysAgo)
	disclosure := models.VulnerabilityDisclosure{
		ID:          uuid.New(),
		OrgID:       uuid.MustParse(tc().OrgID),
		Cve:         "CVE-2025-OLDBEFORE",
		Title:       "Old SLA Violation",
		Description: "Received long ago",
		Severity:    "high",
		Status:      "received",
		ReceivedAt:  receivedAt,
		CreatedAt:   receivedAt,
		UpdatedAt:   receivedAt,
	}
	return tc().DB.Create(&disclosure).Error
}

func disclosureSeedSecondOrg() error {
	secondOrgID := uuid.New()
	org := models.Organization{
		ID:                  secondOrgID,
		Name:                "Second Corp",
		Slug:                "second-corp",
		Tier:                "enterprise",
		EnisaSubmissionMode: "export",
		CsafScope:           "per_sbom",
		PdfTemplate:         "generic",
		SlaTrackingMode:     "per_cve",
		SlaMode:             "fully_automatic",
	}
	if err := tc().DB.Create(&org).Error; err != nil {
		return fmt.Errorf("failed to create second org: %w", err)
	}
	var err error
	secondOrgTokens, err = testcontext.GenerateTokens(secondOrgID.String())
	if err != nil {
		return fmt.Errorf("failed to generate tokens for second org: %w", err)
	}
	return nil
}

func disclosureListSecondOrg() error {
	req := httptest.NewRequest(http.MethodGet, "/api/disclosures", nil)
	req.Header.Set("Authorization", "Bearer "+secondOrgTokens.AdminToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

// disclosureCreateMissingCVE submits a disclosure without the required cve field, expecting 422.
func disclosureCreateMissingCVE() error {
	body := `{"title":"Missing CVE Field","description":"Test","severity":"high"}`
	req := httptest.NewRequest(http.MethodPost, "/api/disclosures", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	req.Header.Set("Content-Type", "application/json")
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

// disclosureGetArbitraryByID fetches a disclosure by an explicit ID string.
func disclosureGetArbitraryByID(id string) error {
	req := httptest.NewRequest(http.MethodGet, "/api/disclosures/"+id, nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

// disclosureUpdateArbitraryStatus updates the status of a disclosure by an explicit ID string.
func disclosureUpdateArbitraryStatus(id, status string) error {
	body := fmt.Sprintf(`{"status":"%s"}`, status)
	req := httptest.NewRequest(http.MethodPut, "/api/disclosures/"+id+"/status", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	req.Header.Set("Content-Type", "application/json")
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}
