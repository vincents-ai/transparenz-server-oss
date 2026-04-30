// Copyright (c) 2026 Vincent Palmer. All rights reserved.

package bdd

import (
	"context"
	"testing"

	"github.com/cucumber/godog"
	"github.com/google/uuid"
	"github.com/transparenz/transparenz-server-oss/bdd/testcontext"
)

func TestFeatures(t *testing.T) {
	if _, err := testcontext.GetSharedContext(); err != nil {
		t.Skipf("skipping BDD tests: external services unavailable: %v", err)
	}

	suite := godog.TestSuite{
		Options: &godog.Options{
			Format:      "pretty",
			Paths:       []string{"features"},
			Concurrency: 1,
		},
		ScenarioInitializer: featureContext,
	}

	if suite.Run() != 0 {
		t.Fatal("non-zero status returned, failed to run feature tests")
	}
}

func featureContext(s *godog.ScenarioContext) {
	s.Before(func(ctx context.Context, sc *godog.Scenario) (context.Context, error) {
		if err := testcontext.ResetTestData(); err != nil {
			return ctx, err
		}
		lastResponse = nil
		lastSbomID = ""
		lastSbomWebhookID = ""
		lastSbomWebhookSecret = ""
		sbomUploadCount = 0
		lastVexID = ""
		lastDisclosureID = ""
		lastEnisaSubmissionID = ""
		gbLastWebhookID = ""
		gbLastWebhookSecret = ""
		mtOrgBWebhookID = ""
		securityKeyID = ""
		lifecycleScanID = ""
		auditEventID = uuid.UUID{}
		csafEnisaSubmissionID = ""
		if enisaMock != nil {
			enisaMock.Reset()
		}
		return ctx, nil
	})

	RegisterCommonSteps(s)
	RegisterAuditSteps(s)
	RegisterSbomSteps(s)
	RegisterScanSteps(s)
	RegisterComplianceSteps(s)
	RegisterVexSteps(s)
	RegisterDisclosureSteps(s)
	RegisterGreenboneSteps(s)
	RegisterEnisaSteps(s)
	RegisterAlertsSteps(s)
	RegisterTelemetrySteps(s)
	RegisterMultiTenantSteps(s)
	RegisterSigningSteps(s)
	RegisterSecuritySteps(s)
	RegisterLifecycleSteps(s)
	RegisterAuditTamperSteps(s)
	RegisterAnalystWorkflowSteps(s)
	RegisterExtendedSteps(s)
	RegisterCSAFSteps(s)
}
