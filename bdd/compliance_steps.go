// Copyright (c) 2026 Vincent Palmer. All rights reserved.
package bdd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/cucumber/godog"
	"github.com/google/uuid"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
)

func RegisterComplianceSteps(s *godog.ScenarioContext) {
	s.Step(`^an SLA tracking entry exists for CVE "([^"]*)"$`, complianceSeedSlaEntry)
	s.Step(`^an SLA tracking entry exists with status "([^"]*)"$`, complianceSeedViolatedSlaEntry)
	s.Step(`^a critical vulnerability discovered (\d+) days ago$`, complianceSeedOldCriticalVuln)
	s.Step(`^I get the compliance status$`, complianceGetStatus)
	s.Step(`^I list SLA tracking entries$`, complianceListSla)
	s.Step(`^I report CVE "([^"]*)" as exploited with role "([^"]*)"$`, complianceReportExploited)
	s.Step(`^a compliance event of type "([^"]*)" should exist$`, complianceCheckEventRecorded)
}

func complianceSeedSlaEntry(cve string) error {
	sla := models.SlaTracking{
		ID:       uuid.New(),
		OrgID:    uuid.MustParse(tc().OrgID),
		Cve:      cve,
		Deadline: time.Now().Add(72 * time.Hour),
		Status:   "pending",
	}
	return tc().DB.Create(&sla).Error
}

func complianceSeedViolatedSlaEntry(status string) error {
	sla := models.SlaTracking{
		ID:       uuid.New(),
		OrgID:    uuid.MustParse(tc().OrgID),
		Cve:      "CVE-2024-BREACH",
		Deadline: time.Now().Add(-96 * time.Hour),
		Status:   status,
	}
	return tc().DB.Create(&sla).Error
}

func complianceSeedOldCriticalVuln(days int) error {
	discoveredAt := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
	vuln := models.Vulnerability{
		ID:           uuid.New(),
		OrgID:        uuid.MustParse(tc().OrgID),
		Cve:          "CVE-2024-BREACH",
		Severity:     "critical",
		DiscoveredAt: discoveredAt,
	}
	return tc().DB.Create(&vuln).Error
}

func complianceGetStatus() error {
	req, _ := http.NewRequest(http.MethodGet, "/api/compliance/status", nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.ComplianceOfficerToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func complianceListSla() error {
	req, _ := http.NewRequest(http.MethodGet, "/api/compliance/sla", nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.ComplianceOfficerToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func complianceReportExploited(cve, role string) error {
	var token string
	switch role {
	case "admin":
		token = tc().Tokens.AdminToken
	case "compliance_officer":
		token = tc().Tokens.ComplianceOfficerToken
	default:
		token = tc().Tokens.UserToken
	}
	body, _ := json.Marshal(map[string]string{"cve": cve})
	req, _ := http.NewRequest(http.MethodPost, "/api/compliance/exploited", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func complianceCheckEventRecorded(eventType string) error {
	orgID := uuid.MustParse(tc().OrgID)
	var count int64
	err := tc().DB.Model(&models.ComplianceEvent{}).
		Where("org_id = ? AND event_type = ?", orgID, eventType).
		Count(&count).Error
	if err != nil {
		return fmt.Errorf("failed to query compliance events: %w", err)
	}
	if count == 0 {
		return fmt.Errorf("expected compliance event of type %q but found 0", eventType)
	}
	return nil
}
