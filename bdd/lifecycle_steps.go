// Copyright (c) 2026 Vincent Palmer. All rights reserved.
package bdd

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/google/uuid"
	"github.com/transparenz/transparenz-server-oss/internal/models"
)

var lifecycleScanID string

func RegisterLifecycleSteps(s *godog.ScenarioContext) {
	// Vulnerability feed seeding
	s.Step(`^a vulnerability feed entry exists for (CVE-[\d-]+) with severity "([^"]*)" and CVSS ([\d.]+)$`, lifecycleSeedFeedEntry)

	// Enriched scan results
	s.Step(`^a scan exists for SBOM "([^"]*)" with vulnerability "([^"]*)"$`, lifecycleSeedScanWithVuln)
	s.Step(`^I get scan vulnerabilities for the last scan$`, lifecycleGetScanVulns)

	// Webhook HMAC
	s.Step(`^I send an SBOM via webhook with invalid signature$`, lifecycleWebhookInvalidSig)

	// Exploited vulnerability verification
	s.Step(`^the vulnerability "([^"]*)" should be marked as exploited in the wild$`, lifecycleAssertExploited)

	// GRC mappings
	s.Step(`^a GRC mapping exists for CVE "([^"]*)" with framework "([^"]*)" and control "([^"]*)"$`, lifecycleSeedGRCMapping)
	s.Step(`^a GRC mapping exists for the organization$`, lifecycleSeedOrgGRCMapping)

	// Approaching SLAs
	s.Step(`^an SLA tracking entry exists for CVE "([^"]*)" with deadline (\d+) hours from now$`, lifecycleSeedApproachingSLA)
	s.Step(`^I list approaching SLA tracking entries$`, lifecycleListApproachingSLAs)
	s.Step(`^I list SLA entries with status "([^"]*)"$`, lifecycleListSLAsByStatus)
	s.Step(`^all SLA entries should have status "([^"]*)"$`, lifecycleAssertAllSlaStatus)

	// Export
	s.Step(`^a compliance event of type "([^"]*)" with severity "([^"]*)" exists$`, lifecycleSeedComplianceEvent)
	s.Step(`^I export the audit trail as CSV$`, lifecycleExportCSV)
	s.Step(`^I export the audit trail as PDF$`, lifecycleExportPDF)
	s.Step(`^I export the audit trail as CSV with role "([^"]*)"$`, lifecycleExportCSVRole)
	s.Step(`^the CSV should contain a header row$`, lifecycleAssertCSVHeader)

	// Enriched SBOM export
	s.Step(`^I export the enriched SBOM with ID "([^"]*)"$`, lifecycleExportEnrichedSBOM)

	// Feed status
	s.Step(`^vulnerability feed entries from multiple sources$`, lifecycleSeedFeedEntries)
	s.Step(`^I get the feed status$`, lifecycleGetFeedStatus)
}

// --- Vulnerability Feed ---

func lifecycleSeedFeedEntry(cve, severity string, cvss float64) error {
	feed := models.VulnerabilityFeed{
		ID:            uuid.New(),
		Cve:           cve,
		EnisaSeverity: severity,
		BaseScore:     &cvss,
		LastSyncedAt:  time.Now(),
	}
	return tc().DB.Create(&feed).Error
}

// --- Enriched Scan Results ---

func lifecycleSeedScanWithVuln(sbomIDStr, cve string) error {
	sbomID, err := uuid.Parse(sbomIDStr)
	if err != nil {
		return fmt.Errorf("invalid SBOM ID: %w", err)
	}
	orgID := uuid.MustParse(tc().OrgID)

	scan := models.Scan{
		ID:     uuid.New(),
		OrgID:  orgID,
		SbomID: sbomID,
		Status: "completed",
	}
	if err := tc().DB.Create(&scan).Error; err != nil {
		return fmt.Errorf("create scan: %w", err)
	}
	lifecycleScanID = scan.ID.String()

	// Seed vulnerability
	vuln := models.Vulnerability{
		ID:           uuid.New(),
		OrgID:        orgID,
		Cve:          cve,
		Severity:     "high",
		DiscoveredAt: time.Now(),
	}
	if err := tc().DB.Create(&vuln).Error; err != nil {
		return fmt.Errorf("create vuln: %w", err)
	}

	// Link scan to vulnerability
	scanVuln := models.ScanVulnerability{
		ID:              uuid.New(),
		ScanID:          scan.ID,
		VulnerabilityID: vuln.ID,
	}
	if err := tc().DB.Create(&scanVuln).Error; err != nil {
		return fmt.Errorf("create scan_vulnerability: %w", err)
	}

	return nil
}

func lifecycleGetScanVulns() error {
	url := fmt.Sprintf("/api/scans/%s/vulnerabilities", lifecycleScanID)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

// --- Webhook HMAC ---

func lifecycleWebhookInvalidSig() error {
	sbomContent := `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1}`
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("file", "invalid-sig.cdx.json")
	_, _ = part.Write([]byte(sbomContent))
	_ = writer.Close()

	url := "/api/v1/sbom/webhook/" + lastSbomWebhookID
	req := httptest.NewRequest(http.MethodPost, url, &buf)
	req.Header.Set("X-SBOM-Token", lastSbomWebhookSecret)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	// Intentionally set an invalid HMAC signature
	req.Header.Set("X-Webhook-Signature", "deadbeef")
	req.Header.Set("X-Webhook-Timestamp", fmt.Sprintf("%d", time.Now().Unix()))

	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

// --- Exploited Vulnerability ---

func lifecycleAssertExploited(cve string) error {
	orgID := uuid.MustParse(tc().OrgID)
	var vuln models.Vulnerability
	if err := tc().DB.Where("org_id = ? AND cve = ?", orgID, cve).First(&vuln).Error; err != nil {
		return fmt.Errorf("vulnerability %s not found: %w", cve, err)
	}
	if !vuln.ExploitedInWild {
		return fmt.Errorf("expected CVE %s to be marked as exploited_in_wild, but it is not", cve)
	}
	return nil
}

// --- GRC Mappings ---

func lifecycleSeedGRCMapping(cve, framework, controlID string) error {
	orgID := uuid.MustParse(tc().OrgID)

	// Find the vulnerability for this CVE
	var vuln models.Vulnerability
	if err := tc().DB.Where("org_id = ? AND cve = ?", orgID, cve).First(&vuln).Error; err != nil {
		return fmt.Errorf("vulnerability %s not found: %w", cve, err)
	}

	mapping := models.GRCMapping{
		ID:              uuid.New(),
		OrgID:           orgID,
		VulnerabilityID: &vuln.ID,
		ControlID:       controlID,
		Framework:       framework,
		MappingType:     "direct",
		Confidence:      0.95,
		Evidence:        "Automated mapping based on CVE analysis",
	}
	return tc().DB.Create(&mapping).Error
}

func lifecycleSeedOrgGRCMapping() error {
	orgID := uuid.MustParse(tc().OrgID)
	vulnID := uuid.New()
	// Create a placeholder vulnerability for the GRC mapping
	vuln := models.Vulnerability{
		ID:           vulnID,
		OrgID:        orgID,
		Cve:          "CVE-2026-GRC-EXPORT",
		Severity:     "medium",
		DiscoveredAt: time.Now(),
	}
	if err := tc().DB.Create(&vuln).Error; err != nil {
		return fmt.Errorf("create vuln for GRC: %w", err)
	}

	mapping := models.GRCMapping{
		ID:              uuid.New(),
		OrgID:           orgID,
		VulnerabilityID: &vulnID,
		ControlID:       "ISO.27001.A.12.6",
		Framework:       "ISO-27001",
		MappingType:     "direct",
		Confidence:      0.9,
		Evidence:        "Vulnerability management control mapping",
	}
	return tc().DB.Create(&mapping).Error
}

// --- Approaching SLAs ---

func lifecycleSeedApproachingSLA(cve string, hours int) error {
	sla := models.SlaTracking{
		ID:       uuid.New(),
		OrgID:    uuid.MustParse(tc().OrgID),
		Cve:      cve,
		Deadline: time.Now().Add(time.Duration(hours) * time.Hour),
		Status:   "pending",
	}
	return tc().DB.Create(&sla).Error
}

func lifecycleListApproachingSLAs() error {
	req := httptest.NewRequest(http.MethodGet, "/api/compliance/sla?approaching=true", nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.ComplianceOfficerToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func lifecycleListSLAsByStatus(status string) error {
	url := fmt.Sprintf("/api/compliance/sla?status=%s", status)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.ComplianceOfficerToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func lifecycleAssertAllSlaStatus(expected string) error {
	if lastResponse == nil {
		return fmt.Errorf("no response recorded")
	}
	var body struct {
		Data []struct {
			Status string `json:"status"`
		} `json:"data"`
	}
	if err := json.Unmarshal(lastResponse.Body.Bytes(), &body); err != nil {
		return fmt.Errorf("failed to parse SLA response: %w", err)
	}
	if len(body.Data) == 0 {
		return fmt.Errorf("expected SLA entries but got 0")
	}
	for _, sla := range body.Data {
		if sla.Status != expected {
			return fmt.Errorf("expected SLA status %q, got %q", expected, sla.Status)
		}
	}
	return nil
}

// --- Compliance Events ---

func lifecycleSeedComplianceEvent(eventType, severity string) error {
	orgID := uuid.MustParse(tc().OrgID)
	event := models.ComplianceEvent{
		OrgID:     orgID,
		EventType: eventType,
		Severity:  severity,
		Cve:       "CVE-2026-EVENT",
		Metadata:  models.JSONMap{"source": "lifecycle-test"},
	}
	return tc().DB.Create(&event).Error
}

// --- Export ---

func lifecycleExportCSV() error {
	req := httptest.NewRequest(http.MethodGet, "/api/export/audit?format=csv", nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.ComplianceOfficerToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func lifecycleExportPDF() error {
	req := httptest.NewRequest(http.MethodGet, "/api/export/audit?format=pdf", nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.ComplianceOfficerToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func lifecycleExportCSVRole(role string) error {
	var token string
	switch role {
	case "user":
		token = tc().Tokens.UserToken
	default:
		token = tc().Tokens.AdminToken
	}
	req := httptest.NewRequest(http.MethodGet, "/api/export/audit?format=csv", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func lifecycleAssertCSVHeader() error {
	if lastResponse == nil {
		return fmt.Errorf("no response recorded")
	}
	body := lastResponse.Body.String()
	reader := csv.NewReader(strings.NewReader(body))
	record, err := reader.Read()
	if err == io.EOF {
		return fmt.Errorf("CSV is empty")
	}
	if err != nil {
		return fmt.Errorf("failed to read CSV: %w", err)
	}
	expected := []string{"Timestamp", "Event Type", "Severity", "CVE", "Details"}
	if len(record) < len(expected) {
		return fmt.Errorf("CSV header has %d columns, expected at least %d: %v", len(record), len(expected), record)
	}
	for i, col := range expected {
		if record[i] != col {
			return fmt.Errorf("CSV header column %d: expected %q, got %q", i, col, record[i])
		}
	}
	return nil
}

// --- Enriched SBOM Export ---

func lifecycleExportEnrichedSBOM(sbomID string) error {
	url := fmt.Sprintf("/api/export/enriched-sbom/%s", sbomID)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.ComplianceOfficerToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

// --- Feed Status ---

func lifecycleSeedFeedEntries() error {
	now := time.Now()
	feeds := []models.VulnerabilityFeed{
		{
			ID:            uuid.New(),
			Cve:           "CVE-2026-FEED-BSI",
			BsiAdvisoryID: "WID-SEC-2026-0001",
			BsiSeverity:   "high",
			LastSyncedAt:  now,
		},
		{
			ID:            uuid.New(),
			Cve:           "CVE-2026-FEED-EUV",
			EnisaEuvdID:   "EUVD-2026-0001",
			EnisaSeverity: "critical",
			LastSyncedAt:  now,
		},
		{
			ID:            uuid.New(),
			Cve:           "CVE-2026-FEED-KEV",
			KevExploited:  true,
			KevDateAdded:  &now,
			LastSyncedAt:  now,
		},
	}
	for _, f := range feeds {
		if err := tc().DB.Create(&f).Error; err != nil {
			return fmt.Errorf("seed feed entry %s: %w", f.Cve, err)
		}
	}
	return nil
}

func lifecycleGetFeedStatus() error {
	req := httptest.NewRequest(http.MethodGet, "/api/feed-status", nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}
