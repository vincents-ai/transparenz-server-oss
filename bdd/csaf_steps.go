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
	"github.com/transparenz/transparenz-server-oss/internal/services"
)

var csafEnisaSubmissionID string
var enisaMock *enisaMockServer

func RegisterCSAFSteps(s *godog.ScenarioContext) {
	// CSAF Provider (authenticated /api/csaf/ endpoints)
	s.Step(`^I request the CSAF provider metadata$`, csafGetProviderMetadata)
	s.Step(`^the provider role should be "([^"]*)"$`, csafAssertRole)
	s.Step(`^the metadata version should be "([^"]*)"$`, csafAssertVersion)
	s.Step(`^I list CSAF advisory documents$`, csafListAdvisories)
	s.Step(`^I get the last CSAF advisory$`, csafGetLastAdvisory)
	s.Step(`^I get CSAF advisory with ID "([^"]*)"$`, csafGetAdvisoryByID)
	s.Step(`^the response should contain at least (\d+) advisory$`, csafAssertMinAdvisoryCount)
	s.Step(`^I download the CSAF changes.csv$`, csafDownloadChanges)
	s.Step(`^an ENISA submission exists for CVE "([^"]*)"$`, csafSeedEnisaSubmission)

	// CSAF Well-Known (public /.well-known/csaf/ endpoints)
	s.Step(`^I request the well-known CSAF provider metadata for org "([^"]*)"$`, wkGetProviderMetadata)
	s.Step(`^I request the well-known CSAF provider metadata for org "([^"]*)" without auth$`, wkGetProviderMetadataNoAuth)
	s.Step(`^the canonical URL should contain "([^"]*)"$`, wkAssertCanonicalURL)
	s.Step(`^I request the well-known CSAF advisory for org "([^"]*)"$`, wkGetAdvisory)
	s.Step(`^I download the well-known CSAF changes.csv for org "([^"]*)"$`, wkDownloadChanges)

	// ENISA API Mode
	s.Step(`^the organization has ENISA submission mode "([^"]*)"$`, enisaSetSubmissionMode)
	s.Step(`^the ENISA API endpoint is configured with a valid mock server$`, enisaConfigureMock)
	s.Step(`^the ENISA mock server should have received (\d+) submissions?$`, enisaAssertMockSubmissions)
}

// --- CSAF Provider ---

func csafGetProviderMetadata() error {
	req := httptest.NewRequest(http.MethodGet, "/api/csaf/provider-metadata.json", nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func csafAssertRole(expected string) error {
	if lastResponse == nil {
		return fmt.Errorf("no response recorded")
	}
	var body map[string]interface{}
	if err := json.Unmarshal(lastResponse.Body.Bytes(), &body); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	role, ok := body["role"].(string)
	if !ok {
		return fmt.Errorf("response missing role field")
	}
	if role != expected {
		return fmt.Errorf("expected role %q, got %q", expected, role)
	}
	return nil
}

func csafAssertVersion(expected string) error {
	if lastResponse == nil {
		return fmt.Errorf("no response recorded")
	}
	var body map[string]interface{}
	if err := json.Unmarshal(lastResponse.Body.Bytes(), &body); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	version, ok := body["metadata_version"].(string)
	if !ok {
		return fmt.Errorf("response missing metadata_version field")
	}
	if version != expected {
		return fmt.Errorf("expected metadata_version %q, got %q", expected, version)
	}
	return nil
}

func csafListAdvisories() error {
	req := httptest.NewRequest(http.MethodGet, "/api/csaf/advisories", nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func csafGetLastAdvisory() error {
	req := httptest.NewRequest(http.MethodGet, "/api/csaf/advisories/"+csafEnisaSubmissionID, nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func csafGetAdvisoryByID(id string) error {
	req := httptest.NewRequest(http.MethodGet, "/api/csaf/advisories/"+id, nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func csafAssertMinAdvisoryCount(min int) error {
	if lastResponse == nil {
		return fmt.Errorf("no response recorded")
	}
	var body struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal(lastResponse.Body.Bytes(), &body); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	if body.Count < min {
		return fmt.Errorf("expected at least %d advisories, got %d", min, body.Count)
	}
	return nil
}

func csafDownloadChanges() error {
	req := httptest.NewRequest(http.MethodGet, "/api/csaf/changes.csv", nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

// csafSeedEnisaSubmission creates a full ENISA submission in the database
// by running the CSAF generator and persisting the result.
func csafSeedEnisaSubmission(cve string) error {
	// Use the mock submitter pattern — just create a submission record directly
	sub := models.EnisaSubmission{
		ID: uuid.New(),
		SubmissionID: fmt.Sprintf("CSAF-%s", uuid.New().String()[:8]),
		CsafDocument: models.JSONMap{
			"document": map[string]interface{}{
				"title":        fmt.Sprintf("CSAF Advisory - %s", cve),
				"category":     "csaf_2.0",
				"csaf_version": "2.0",
				"tracking": map[string]interface{}{
					"id":      uuid.New().String(),
					"status":  "final",
					"version": "1.0",
				},
			},
			"vulnerabilities": []map[string]interface{}{
				{"cve": cve},
			},
		},
		Status: "submitted",
	}

	if err := tc().DB.Create(&sub).Error; err != nil {
		return fmt.Errorf("failed to create ENISA submission: %w", err)
	}

	csafEnisaSubmissionID = sub.ID.String()
	return nil
}

// --- ENISA API Mode ---

func enisaSetSubmissionMode(mode string) error {
	return tc().DB.Model(&models.Organization{}).
		Where("id = ?", tc().OrgID).
		Update("enisa_submission_mode", mode).Error
}

func enisaConfigureMock() error {
	if enisaMock == nil {
		enisaMock = newEnisaMockServer()
	}

	// Update the org to point to the mock server
	endpoint := enisaMock.URL() + "/submissions"
	return tc().DB.Model(&models.Organization{}).
		Where("id = ?", tc().OrgID).
		Updates(map[string]interface{}{
			"enisa_api_endpoint":     endpoint,
			"enisa_submission_mode":  "api",
		}).Error
}

func enisaAssertMockSubmissions(expected int) error {
	if enisaMock == nil {
		return fmt.Errorf("ENISA mock server not started")
	}
	subs := enisaMock.Submissions()
	if len(subs) != expected {
		return fmt.Errorf("expected %d mock ENISA submissions, got %d", expected, len(subs))
	}
	return nil
}

// Ensure imports used
var _ services.CSAFGenerator
var _ = http.MethodGet

// --- Well-Known CSAF Endpoints (public, no auth) ---

func wkGetProviderMetadata(orgSlug string) error {
	url := fmt.Sprintf("/.well-known/csaf/%s/provider-metadata.json", orgSlug)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func wkGetProviderMetadataNoAuth(orgSlug string) error {
	// Same as wkGetProviderMetadata — well-known endpoints have no auth
	return wkGetProviderMetadata(orgSlug)
}

func wkAssertCanonicalURL(substring string) error {
	if lastResponse == nil {
		return fmt.Errorf("no response recorded")
	}
	var body map[string]interface{}
	if err := json.Unmarshal(lastResponse.Body.Bytes(), &body); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	canonical, ok := body["canonical_url"].(string)
	if !ok {
		return fmt.Errorf("response missing canonical_url field")
	}
	if !strings.Contains(canonical, substring) {
		return fmt.Errorf("canonical_url %q does not contain %q", canonical, substring)
	}
	return nil
}

func wkGetAdvisory(orgSlug string) error {
	if csafEnisaSubmissionID == "" {
		return fmt.Errorf("no ENISA submission ID available — seed one first")
	}
	url := fmt.Sprintf("/.well-known/csaf/%s/%s.json", orgSlug, csafEnisaSubmissionID)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func wkDownloadChanges(orgSlug string) error {
	url := fmt.Sprintf("/.well-known/csaf/%s/changes.csv", orgSlug)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}
