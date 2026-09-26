// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.

package cra

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var openedAt = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

func openFixture(t *testing.T) (Assessment, OpenRequest) {
	t.Helper()

	assessment, err := ResolveExposure(ExposureInput{
		OrgID:     uuid.New(),
		VulnID:    uuid.New(),
		CVE:       "CVE-2026-31337",
		Exposures: []ProductExposure{exposure("gateway", "2.2.0")},
		Signals:   []ExploitationSignal{signal(EvidenceSourceInternalTelemetry, true)},
		Awareness: awareAt(t, "2026-09-26T06:00:00Z"),
	}, openedAt)
	require.NoError(t, err)

	assessment.VulnID = uuid.New()
	assessment.OrgID = uuid.New()

	return assessment, OpenRequest{
		ReportID:          uuid.New(),
		OrgID:             assessment.OrgID,
		ExposureProductID: "gateway",
		EventType:         EventTypeAEV,
		Exploitation:      exploitation,
		Awareness:         awareAt(t, "2026-09-26T06:00:00Z"),
		Actor:             "user:sec@example.eu",
		Now:               openedAt,
	}
}

func TestOpenFromAssessmentProducesAReportCarryingTheCompositionEvidence(t *testing.T) {
	a, req := openFixture(t)
	r, err := OpenFromAssessment(a, req)
	require.NoError(t, err)

	assert.Equal(t, StateDetected, r.State, "a new report starts at DETECTED, not reportable")
	assert.Equal(t, EventTypeAEV, r.EventType)
	assert.Equal(t, "CVE-2026-31337", r.VulnerabilityID)
	assert.Contains(t, r.Title, "libfoo")
	assert.Contains(t, r.Description, "2.2.0",
		"the report records which component version reached the product")

	require.NotEmpty(t, r.Decisions)
	found := false
	for _, d := range r.Decisions {
		for _, e := range d.Evidence {
			if e != "" && containsAll(e, "component=libfoo@2.2.0") {
				found = true
			}
		}
	}
	assert.True(t, found, "the composition claim must be retained as evidence on the report")
}

func TestOpenCarriesExistingVexStatementsOntoTheDecisionLog(t *testing.T) {
	assessment, req := openFixture(t)
	assessment.Prioritised[0].VexStatements = []VexClaim{{
		StatementID:   uuid.New(),
		Status:        "active",
		Justification: "vulnerable_code_not_in_execute_path",
	}}

	r, err := OpenFromAssessment(assessment, req)
	require.NoError(t, err)

	// The report still opens — a not_affected claim is evidence, not a bar —
	// but the claim is on the record so the determination can be reviewed.
	var mentioned bool
	for _, d := range r.Decisions {
		if containsAll(d.Reason, "VEX statement on record") {
			mentioned = true
		}
	}
	assert.True(t, mentioned, "opening over a not_affected claim must record that the claim existed")
}

func TestOpenRefusesWithoutAnAccountableActor(t *testing.T) {
	a, req := openFixture(t)
	req.Actor = ""
	_, err := OpenFromAssessment(a, req)
	require.ErrorIs(t, err, ErrAssessmentIncomplete)
}

func TestOpenRefusesWithoutAwareness(t *testing.T) {
	a, req := openFixture(t)
	req.Awareness = Awareness{}
	_, err := OpenFromAssessment(a, req)
	require.ErrorIs(t, err, ErrAssessmentIncomplete,
		"a report with no evidenced awareness has no clock and cannot be filed")
}

func TestOpeningWithoutExploitationEvidenceIsAllowedButClassificationIsNot(t *testing.T) {
	// A report is opened at DETECTED with whatever is known so far. The
	// refusal belongs at the classification step, where the claim being made is
	// "this is actively exploited" and the evidence for it is the artefact.
	// Refusing to open instead would prevent an operator recording what they
	// do not yet know, which is exactly when the clock is running.
	a, req := openFixture(t)
	req.Exploitation = nil

	r, err := OpenFromAssessment(a, req)
	require.NoError(t, err)
	assert.Equal(t, StateDetected, r.State)

	r, err = r.TransitionTo(StateAssessingReportability, req.Actor, "assessing", req.Now)
	require.NoError(t, err)

	_, err = r.TransitionTo(StateReportableAEV, req.Actor, "severity is critical", req.Now)
	require.Error(t, err, "an AEV cannot be determined without exploitation evidence")
	assert.Equal(t, StateAssessingReportability, r.State,
		"a refused classification must not half-apply")
}

func TestOpenRefusesAProductThatIsNotInTheAssessment(t *testing.T) {
	a, req := openFixture(t)
	req.ExposureProductID = "some-product-we-do-not-ship"
	_, err := OpenFromAssessment(a, req)
	require.ErrorIs(t, err, ErrAssessmentIncomplete,
		"a report cannot rest on a composition the evidence does not show")
}

func TestOpenRequiresNamingAProductWhenSeveralAreExposed(t *testing.T) {
	a, req := openFixture(t)
	a.Prioritised = append(a.Prioritised, PrioritisedExposure{
		ProductExposure: exposure("analytics", "0.9.1"),
	})
	req.ExposureProductID = ""
	_, err := OpenFromAssessment(a, req)
	require.ErrorIs(t, err, ErrAssessmentIncomplete,
		"picking for the caller would attribute the duty to the wrong product")
}

func TestOpenAcceptsASingleExposureWithoutNamingIt(t *testing.T) {
	a, req := openFixture(t)
	req.ExposureProductID = ""
	r, err := OpenFromAssessment(a, req)
	require.NoError(t, err, "an unambiguous assessment needs no disambiguation")
	assert.Equal(t, StateDetected, r.State)
}

func TestOpenedReportContinuesThroughTheWorkflowWithACorrectClock(t *testing.T) {
	a, req := openFixture(t)
	r, err := OpenFromAssessment(a, req)
	require.NoError(t, err)

	var err2 error
	r, err2 = r.TransitionTo(StateAssessingReportability, req.Actor, "assessing", req.Now)
	require.NoError(t, err2)
	r, err2 = r.TransitionTo(StateReportableAEV, req.Actor, "exploitation evidence accepted", req.Now)
	require.NoError(t, err2)

	// Awareness was 06:00, so the 24h early warning is due the next morning.
	deadlines, err := r.Deadlines()
	require.NoError(t, err)
	require.NotEmpty(t, deadlines)
	assert.Equal(t, "2026-09-27T06:00:00Z", deadlines[0].Due.Format(time.RFC3339))
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		found := false
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
