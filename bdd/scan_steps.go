// Copyright (c) 2026 Vincent Palmer. All rights reserved.
package bdd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/cucumber/godog"
	"github.com/google/uuid"
	"github.com/transparenz/transparenz-server-oss/internal/models"
)

func RegisterScanSteps(s *godog.ScenarioContext) {
	s.Step(`^an SBOM has been uploaded with ID "([^"]*)"$`, scanSeedSBOM)
	s.Step(`^I create a scan for SBOM "([^"]*)"$`, scanCreateScan)
	s.Step(`^the scan should have status "([^"]*)"$`, scanHasStatus)
	s.Step(`^I list scans$`, scanListScans)
	s.Step(`^I list vulnerabilities$`, scanListVulnerabilities)
	s.Step(`^I list vulnerabilities filtered by severity "([^"]*)"$`, scanListVulnerabilitiesBySeverity)
	s.Step(`^I get vulnerability with CVE "([^"]*)"$`, scanGetVulnerability)
	s.Step(`^the vulnerability should have severity "([^"]*)"$`, scanVulnHasSeverity)
}

func scanSeedSBOM(sbomID string) error {
	parsedID, err := uuid.Parse(sbomID)
	if err != nil {
		return fmt.Errorf("invalid SBOM ID: %w", err)
	}
	sbom := models.SbomUpload{
		ID:        parsedID,
		OrgID:     uuid.MustParse(tc().OrgID),
		Filename:  "test-sbom.json",
		Format:    "cyclonedx-json",
		SizeBytes: 1024,
		SHA256:    "abc123def456",
		Document:  json.RawMessage(`{"bomFormat":"CycloneDX"}`),
	}
	return tc().DB.Create(&sbom).Error
}

func scanCreateScan(sbomID string) error {
	body := map[string]string{"sbom_id": sbomID}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/scan", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func scanListScans() error {
	req := httptest.NewRequest(http.MethodGet, "/api/scans", nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func scanListVulnerabilities() error {
	req := httptest.NewRequest(http.MethodGet, "/api/vulnerabilities", nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func scanListVulnerabilitiesBySeverity(severity string) error {
	url := fmt.Sprintf("/api/vulnerabilities?severity=%s", severity)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func scanGetVulnerability(cve string) error {
	url := fmt.Sprintf("/api/vulnerabilities/%s", cve)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func scanHasStatus(expectedStatus string) error {
	if lastResponse == nil {
		return fmt.Errorf("no response recorded")
	}
	var resp struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(lastResponse.Body.Bytes(), &resp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	if resp.Status != expectedStatus {
		return fmt.Errorf("expected scan status %q, got %q", expectedStatus, resp.Status)
	}
	return nil
}

func scanVulnHasSeverity(expectedSeverity string) error {
	if lastResponse == nil {
		return fmt.Errorf("no response recorded")
	}
	var resp struct {
		Severity string `json:"severity"`
	}
	if err := json.Unmarshal(lastResponse.Body.Bytes(), &resp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	if !strings.EqualFold(resp.Severity, expectedSeverity) {
		return fmt.Errorf("expected vulnerability severity %q, got %q", expectedSeverity, resp.Severity)
	}
	return nil
}
