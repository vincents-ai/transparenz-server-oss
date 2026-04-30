// Copyright (c) 2026 Vincent Palmer. Licensed under AGPL-3.0.
package bdd

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strconv"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/google/uuid"
	"github.com/transparenz/transparenz-server-oss/bdd/testcontext"
	"github.com/transparenz/transparenz-server-oss/internal/models"
)

var lastResponse *httptest.ResponseRecorder

func RegisterCommonSteps(s *godog.ScenarioContext) {
	s.Step(`^a running server$`, commonSetupServer)
	s.Step(`^a running server with an authenticated organization$`, commonSetupServerWithOrg)
	s.Step(`^a running VEX server with an authenticated organization$`, commonSetupServerWithOrg)

	s.Step(`^the response status should be (\d+)$`, commonAssertStatus)
	s.Step(`^the response has status code (\d+)$`, commonAssertStatus)
	s.Step(`^the response should contain the field "([^"]*)"$`, commonAssertField)
	s.Step(`^the response should match RFC 7807 problem detail format$`, commonAssertRFC7807)
	s.Step(`^the response Content-Type should be "([^"]*)"$`, commonAssertContentTypeExact)
	s.Step(`^the response Content-Type should contain "([^"]*)"$`, commonAssertContentTypeContains)
	s.Step(`^the response should contain compliance score$`, commonAssertComplianceScore)
	s.Step(`^the response should contain SLA entries$`, commonAssertSlaEntries)
	s.Step(`^the response should indicate SLA breach$`, commonAssertSlaBreach)

	s.Step(`^the organization has (\w+) tier$`, commonSetOrgTier)
	s.Step(`^the organization has "([^"]*)" tier$`, commonSetOrgTier)
	s.Step(`^a vulnerability exists with CVE "([^"]*)" and severity "([^"]*)"$`, commonSeedVulnerability)
	s.Step(`^the organization has a vulnerability with CVE "([^"]*)" and severity "([^"]*)"$`, commonSeedVulnerability)

	s.Step(`^the response should contain (\d+) scans$`, func(n int) error { return commonAssertCount(n, "scans") })
	s.Step(`^the response should contain (\d+) vulnerabilities$`, func(n int) error { return commonAssertCount(n, "vulnerabilities") })
	s.Step(`^the response should contain (\d+) SBOMs$`, func(n int) error { return commonAssertCount(n, "SBOMs") })
	s.Step(`^the response should contain (\d+) disclosures$`, func(n int) error { return commonAssertCount(n, "disclosures") })
	s.Step(`^the response should contain at least (\d+) VEX statement$`, commonAssertMinVexCount)
	s.Step(`^the response should contain at least (\d+) disclosure$`, commonAssertMinDisclosureCount)
	s.Step(`^the response should contain at least (\d+) ENISA submissions?$`, commonAssertMinEnisaCount)

	// ENISA submit
	s.Step(`^I send a POST request to "([^"]*)" as admin$`, commonPostAsAdmin)
}

func commonSetupServer() error {
	_, err := testcontext.GetSharedContext()
	lastResponse = nil
	return err
}

func commonSetupServerWithOrg() error {
	_, err := testcontext.GetSharedContext()
	lastResponse = nil
	return err
}

func tc() *testcontext.TestContext {
	ctx, err := testcontext.GetSharedContext()
	if err != nil {
		panic(fmt.Sprintf("shared context not available: %v", err))
	}
	return ctx
}

func commonAssertStatus(expected int) error {
	if lastResponse == nil {
		return fmt.Errorf("no response recorded")
	}
	if lastResponse.Code != expected {
		return fmt.Errorf("expected status %d, got %d: %s", expected, lastResponse.Code, lastResponse.Body.String())
	}
	return nil
}

func commonAssertField(field string) error {
	if lastResponse == nil {
		return fmt.Errorf("no response recorded")
	}
	var body map[string]interface{}
	if err := json.Unmarshal(lastResponse.Body.Bytes(), &body); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	if _, ok := body[field]; !ok {
		return fmt.Errorf("response missing field %q: %s", field, lastResponse.Body.String())
	}
	return nil
}

func commonAssertRFC7807() error {
	if lastResponse == nil {
		return fmt.Errorf("no response recorded")
	}
	ct := lastResponse.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/problem+json") {
		return fmt.Errorf("expected Content-Type to contain application/problem+json, got %q", ct)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(lastResponse.Body.Bytes(), &body); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	for _, field := range []string{"type", "title", "status"} {
		if _, ok := body[field]; !ok {
			return fmt.Errorf("RFC 7807 response missing required field %q: %s", field, lastResponse.Body.String())
		}
	}
	return nil
}

func commonAssertContentTypeExact(expected string) error {
	if lastResponse == nil {
		return fmt.Errorf("no response recorded")
	}
	ct := lastResponse.Header().Get("Content-Type")
	if ct != expected {
		return fmt.Errorf("expected Content-Type %q, got %q", expected, ct)
	}
	return nil
}

func commonAssertContentTypeContains(sub string) error {
	if lastResponse == nil {
		return fmt.Errorf("no response recorded")
	}
	ct := lastResponse.Header().Get("Content-Type")
	if !strings.Contains(ct, sub) {
		return fmt.Errorf("expected Content-Type to contain %q, got %q", sub, ct)
	}
	return nil
}

func commonAssertComplianceScore() error {
	return commonAssertField("compliance_score")
}

func commonAssertSlaEntries() error {
	if lastResponse == nil {
		return fmt.Errorf("no response recorded")
	}
	var body map[string]interface{}
	if err := json.Unmarshal(lastResponse.Body.Bytes(), &body); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	data, ok := body["data"].([]interface{})
	if !ok {
		return fmt.Errorf("response missing data array: %v", body)
	}
	if len(data) == 0 {
		return fmt.Errorf("expected SLA entries but got 0")
	}
	return nil
}

func commonAssertSlaBreach() error {
	if lastResponse == nil {
		return fmt.Errorf("no response recorded")
	}
	var body map[string]interface{}
	if err := json.Unmarshal(lastResponse.Body.Bytes(), &body); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	violations, ok := body["sla_violations"]
	if !ok {
		return fmt.Errorf("response missing sla_violations field: %v", body)
	}
	v, err := strconv.ParseFloat(fmt.Sprintf("%v", violations), 64)
	if err != nil {
		return fmt.Errorf("failed to parse sla_violations: %w", err)
	}
	if v < 1 {
		return fmt.Errorf("expected SLA breach (sla_violations >= 1), got %v", violations)
	}
	return nil
}

func commonSetOrgTier(tier string) error {
	ctx := tc()
	return testcontext.SetOrgTier(ctx.DB, ctx.OrgID, tier)
}

func commonSeedVulnerability(cve, severity string) error {
	ctx := tc()
	vuln := models.Vulnerability{
		ID:           uuid.New(),
		OrgID:        uuid.MustParse(ctx.OrgID),
		Cve:          cve,
		Severity:     severity,
		DiscoveredAt: time.Now(),
	}
	return ctx.DB.Create(&vuln).Error
}

func commonAssertCount(expected int, kind string) error {
	if lastResponse == nil {
		return fmt.Errorf("no response recorded")
	}
	var body map[string]interface{}
	if err := json.Unmarshal(lastResponse.Body.Bytes(), &body); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	countVal, ok := body["count"]
	if !ok {
		return fmt.Errorf("response missing 'count' field")
	}
	var count int
	switch v := countVal.(type) {
	case float64:
		count = int(v)
	case int:
		count = v
	default:
		return fmt.Errorf("unexpected count type: %T", countVal)
	}
	if count != expected {
		return fmt.Errorf("expected %d %s, got %d", expected, kind, count)
	}
	return nil
}

func commonAssertMinVexCount(min int) error {
	return commonAssertMinCount(min, "VEX statements")
}

func commonAssertMinDisclosureCount(min int) error {
	return commonAssertMinCount(min, "disclosures")
}

func commonAssertMinEnisaCount(min int) error {
	return commonAssertMinCount(min, "ENISA submissions")
}

func commonAssertMinCount(min int, kind string) error {
	if lastResponse == nil {
		return fmt.Errorf("no response recorded")
	}
	var listResp struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal(lastResponse.Body.Bytes(), &listResp); err != nil {
		return fmt.Errorf("failed to parse list response: %w", err)
	}
	if listResp.Count < min {
		return fmt.Errorf("expected at least %d %s, got %d", min, kind, listResp.Count)
	}
	return nil
}

// commonPostAsAdmin sends a POST request as admin.
func commonPostAsAdmin(path string) error {
	req := httptest.NewRequest("POST", path, nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}
