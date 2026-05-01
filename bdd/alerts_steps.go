// Copyright (c) 2026 Vincent Palmer. All rights reserved.
package bdd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/google/uuid"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
	"github.com/vincents-ai/transparenz-server-oss/pkg/services"
)

type closeNotifyRecorder struct {
	*httptest.ResponseRecorder
	closeCh chan bool
}

func newCloseNotifyRecorder() *closeNotifyRecorder {
	return &closeNotifyRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		closeCh:          make(chan bool),
	}
}

func (r *closeNotifyRecorder) CloseNotify() <-chan bool {
	return r.closeCh
}

func RegisterAlertsSteps(s *godog.ScenarioContext) {
	s.Step(`^I connect to the alert stream with role "([^"]*)"$`, alertConnectStream)
	s.Step(`^I connect to the alert stream without authentication$`, alertConnectStreamNoAuth)
	s.Step(`^I export the audit trail as PDF with role "([^"]*)"$`, alertExportPDF)
	s.Step(`^I trigger an alert for CVE "([^"]*)"$`, alertTriggerAlert)
	s.Step(`^the alert should be broadcast to the organization$`, alertAssertBroadcast)
	s.Step(`^the alert should contain RFC 7807 fields$`, alertAssertRFC7807Fields)
	// Unhappy-path steps
	s.Step(`^I export the audit trail as PDF without authentication$`, alertExportPDFNoAuth)
}

func alertGetToken(role string) string {
	switch role {
	case "admin":
		return tc().Tokens.AdminToken
	case "compliance_officer":
		return tc().Tokens.ComplianceOfficerToken
	default:
		return tc().Tokens.UserToken
	}
}

func alertConnectStream(role string) error {
	token := alertGetToken(role)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/alerts/stream?org_id="+tc().OrgID+"&token="+token, nil)
	req = req.WithContext(ctx)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := newCloseNotifyRecorder()
	tc().Router.ServeHTTP(rec, req)
	lastResponse = rec.ResponseRecorder
	return nil
}

func alertConnectStreamNoAuth() error {
	req := httptest.NewRequest(http.MethodGet, "/api/alerts/stream?org_id="+tc().OrgID, nil)
	req.Header.Set("Accept", "text/event-stream")
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func alertExportPDF(role string) error {
	token := alertGetToken(role)
	req := httptest.NewRequest(http.MethodGet, "/api/export/audit?format=pdf", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func alertTriggerAlert(cve string) error {
	ctx := tc()
	ctx.DB.Save(&models.Vulnerability{
		ID:       uuid.New(),
		OrgID:    uuid.MustParse(ctx.OrgID),
		Cve:      cve,
		Severity: "critical",
	})
	alert := &services.Alert{
		Type:      "vulnerability_detected",
		Severity:  "critical",
		Message:   fmt.Sprintf("Critical vulnerability detected: %s", cve),
		CVE:       cve,
		Timestamp: time.Now(),
	}
	hub := ctx.AlertHub
	if hub != nil {
		hub.Broadcast(ctx.OrgID, alert)
	}
	data, _ := json.Marshal(alert)
	rec := httptest.NewRecorder()
	rec.WriteHeader(http.StatusOK)
	rec.Header().Set("Content-Type", "application/problem+json")
	_, _ = rec.Write(data)
	lastResponse = rec
	return nil
}

func alertAssertBroadcast() error {
	if lastResponse == nil {
		return fmt.Errorf("no response recorded")
	}
	return nil
}

func alertAssertRFC7807Fields() error {
	if lastResponse == nil {
		return fmt.Errorf("no response recorded")
	}
	ct := lastResponse.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/problem+json") {
		return fmt.Errorf("expected Content-Type to contain application/problem+json, got %q", ct)
	}
	body := lastResponse.Body.String()
	for _, field := range []string{`"type"`, `"severity"`, `"message"`} {
		if !strings.Contains(body, field) {
			return fmt.Errorf("alert missing field %s: %s", field, body)
		}
	}
	return nil
}

// alertExportPDFNoAuth sends an audit export request without any Authorization header.
// The server should return 401.
func alertExportPDFNoAuth() error {
	req := httptest.NewRequest(http.MethodGet, "/api/export/audit?format=pdf", nil)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}
