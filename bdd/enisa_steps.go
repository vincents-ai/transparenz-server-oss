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
)

var lastEnisaSubmissionID string

func RegisterEnisaSteps(s *godog.ScenarioContext) {
	s.Step(`^I submit an ENISA report for CVE "([^"]*)"$`, enisaSubmitReport)
	s.Step(`^I submit an ENISA report for CVE "([^"]*)" as a regular user$`, enisaSubmitReportAsUser)
	s.Step(`^I list ENISA submissions$`, enisaListSubmissions)
	s.Step(`^I get the last ENISA submission by ID$`, enisaGetByID)
	s.Step(`^I download the last ENISA submission$`, enisaDownload)
	s.Step(`^the response should be a CSAF JSON document$`, enisaAssertCsafDocument)
}

func enisaSubmitReport(cve string) error {
	body, _ := json.Marshal(map[string]string{"cve": cve})
	req := httptest.NewRequest(http.MethodPost, "/api/enisa/submit", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	req.Header.Set("Content-Type", "application/json")
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	if lastResponse.Code == http.StatusAccepted {
		var resp struct {
			SubmissionID string `json:"submission_id"`
		}
		if err := json.Unmarshal(lastResponse.Body.Bytes(), &resp); err == nil {
			lastEnisaSubmissionID = resp.SubmissionID
		}
	}
	return nil
}

func enisaSubmitReportAsUser(cve string) error {
	body, _ := json.Marshal(map[string]string{"cve": cve})
	req := httptest.NewRequest(http.MethodPost, "/api/enisa/submit", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.UserToken)
	req.Header.Set("Content-Type", "application/json")
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func enisaListSubmissions() error {
	req := httptest.NewRequest(http.MethodGet, "/api/enisa/submissions", nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func enisaGetByID() error {
	req := httptest.NewRequest(http.MethodGet, "/api/enisa/submissions/"+lastEnisaSubmissionID, nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func enisaDownload() error {
	req := httptest.NewRequest(http.MethodGet, "/api/enisa/submissions/"+lastEnisaSubmissionID+"/download", nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func enisaAssertCsafDocument() error {
	if lastResponse == nil {
		return fmt.Errorf("no response recorded")
	}
	body := lastResponse.Body.String()
	if !strings.Contains(body, "document") {
		return fmt.Errorf("response does not contain CSAF document: %s", body)
	}
	return nil
}
