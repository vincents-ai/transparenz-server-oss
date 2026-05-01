// Copyright (c) 2026 Vincent Palmer. Licensed under AGPL-3.0.
package bdd

import (
	"context"
	"testing"

	"github.com/cucumber/godog"
	"github.com/vincents-ai/transparenz-server-oss/bdd/testcontext"
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
			TestingT:    t,
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
		sbomUploadCount = 0
		lastVexID = ""
		lastDisclosureID = ""
		csafEnisaSubmissionID = ""
		return ctx, nil
	})

	RegisterCommonSteps(s)
	RegisterAuditSteps(s)
	RegisterSbomSteps(s)
	RegisterScanSteps(s)
	RegisterComplianceSteps(s)
	RegisterVexSteps(s)
	RegisterDisclosureSteps(s)
	RegisterAlertsSteps(s)
	RegisterCSAFSteps(s)
	RegisterExtendedSteps(s)
}
