// Copyright (c) 2026 Vincent Palmer. All rights reserved.
package bdd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/cucumber/godog"
)

var lastVexID string

func RegisterVexSteps(s *godog.ScenarioContext) {
	s.Step(`^I create a VEX statement for CVE "([^"]*)" and product "([^"]*)"$`, vexCreateStatement)
	s.Step(`^the VEX status should be "([^"]*)"$`, vexAssertStatusField)
	s.Step(`^a VEX statement exists for CVE "([^"]*)" and product "([^"]*)"$`, vexCreateStatement)
	s.Step(`^I list VEX statements$`, vexListStatements)
	s.Step(`^I approve the last VEX statement as "([^"]*)"$`, vexApproveStatement)
	s.Step(`^the VEX statement is approved$`, vexApproveLastAsAdmin)
	s.Step(`^I publish the last VEX statement$`, vexPublishStatement)
}

func vexCreateStatement(cve, productID string) error {
	body := fmt.Sprintf(`{"cve":"%s","product_id":"%s"}`, cve, productID)
	req := httptest.NewRequest(http.MethodPost, "/api/vex", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	req.Header.Set("Content-Type", "application/json")
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	if lastResponse.Code == http.StatusCreated {
		var resp struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(lastResponse.Body.Bytes(), &resp); err == nil {
			lastVexID = resp.ID
		}
	}
	return nil
}

func vexAssertStatusField(expected string) error {
	if lastResponse == nil {
		return fmt.Errorf("no response recorded")
	}
	var body map[string]interface{}
	if err := json.Unmarshal(lastResponse.Body.Bytes(), &body); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	status, ok := body["status"].(string)
	if !ok {
		return fmt.Errorf("response missing or non-string status field: %s", lastResponse.Body.String())
	}
	if status != expected {
		return fmt.Errorf("expected status %q, got %q", expected, status)
	}
	return nil
}

func vexListStatements() error {
	req := httptest.NewRequest(http.MethodGet, "/api/vex", nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func vexApproveStatement(role string) error {
	var token string
	switch role {
	case "compliance_officer":
		token = tc().Tokens.ComplianceOfficerToken
	default:
		token = tc().Tokens.AdminToken
	}
	req := httptest.NewRequest(http.MethodPost, "/api/vex/"+lastVexID+"/approve", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func vexApproveLastAsAdmin() error {
	return vexApproveStatement("admin")
}

func vexPublishStatement() error {
	body := strings.NewReader(`{"channel":"file"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/vex/"+lastVexID+"/publish", body)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	req.Header.Set("Content-Type", "application/json")
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}
