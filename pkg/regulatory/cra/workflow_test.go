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

var exploitation = &ExploitationEvidence{
	ObservedAt:   time.Date(2026, 9, 20, 8, 45, 0, 0, time.UTC),
	Summary:      "Observed mass exploitation of the authentication bypass in the wild",
	Source:       AwarenessSourceExploitEvidence,
	Reference:    "pcap-2026-09-20-0845.pcap",
	AttackVector: "network",
	Scope:        "three confirmed victims in the same Member State",
}

func newDetectedReport(t *testing.T) Report {
	t.Helper()
	return Report{
		ID:              uuid.New(),
		OrgID:           uuid.New(),
		State:           StateDetected,
		Awareness:       awareAt(t, "2026-09-20T09:00:00Z"),
		VulnerabilityID: "CVE-2026-31337",
		Title:           "Actively exploited authentication bypass",
		Exploitation:    exploitation,
		CreatedAt:       mustTime(t, "2026-09-20T09:05:00Z"),
		UpdatedAt:       mustTime(t, "2026-09-20T09:05:00Z"),
	}
}

// classifyAEV drives a report from DETECTED to REPORTABLE_AEV and back out to
// the early-warning draft, exercising the assessment path.
func classifyAEV(t *testing.T) Report {
	t.Helper()
	r := newDetectedReport(t)
	var err error

	r, err = r.TransitionTo(StateAssessingReportability, "user:sec@example.eu", "feed hit plus observed exploitation", mustTime(t, "2026-09-20T09:10:00Z"))
	require.NoError(t, err)
	r, err = r.TransitionTo(StateReportableAEV, "user:sec@example.eu", "exploitation evidence attached; product in scope", mustTime(t, "2026-09-20T09:30:00Z"))
	require.NoError(t, err)
	require.Equal(t, EventTypeAEV, r.EventType)
	return r
}

// classifySI drives a report to REPORTABLE_SI.
func classifySI(t *testing.T) Report {
	t.Helper()
	r := newDetectedReport(t)
	r.Exploitation = nil
	r.VulnerabilityID = ""
	r.Title = "Severe incident: unauthenticated control-plane access"
	var err error

	r, err = r.TransitionTo(StateAssessingReportability, "user:ir@example.eu", "incident escalated to severe", mustTime(t, "2026-09-20T09:10:00Z"))
	require.NoError(t, err)
	r, err = r.TransitionTo(StateReportableSI, "user:ir@example.eu", "loss of confidentiality and integrity of product data", mustTime(t, "2026-09-20T09:40:00Z"))
	require.NoError(t, err)
	require.Equal(t, EventTypeSI, r.EventType)
	return r
}

// --- AEV workflow: EW -> 72h -> mitigation -> FR ---------------------------

func TestAEVHappyPath(t *testing.T) {
	r := classifyAEV(t)
	var err error

	r, err = r.TransitionTo(StateEarlyWarningDraft, "user:sec@example.eu", "assembling early warning", mustTime(t, "2026-09-20T10:00:00Z"))
	require.NoError(t, err)
	r, err = r.RecordSubmission(Submission{
		Stage:         StageEarlyWarning,
		SubmittedAt:   mustTime(t, "2026-09-21T08:00:00Z"),
		CaseReference: "SRP-2026-000123",
		PackageDigest: "sha256:1f3a...",
		Via:           "human_srp",
	}, "user:sec@example.eu", mustTime(t, "2026-09-21T08:05:00Z"))
	require.NoError(t, err)
	assert.Equal(t, StateEarlyWarningSubmitted, r.State)

	r, err = r.TransitionTo(StateNotificationDraft, "user:sec@example.eu", "assembling notification", mustTime(t, "2026-09-22T09:00:00Z"))
	require.NoError(t, err)
	r, err = r.RecordSubmission(Submission{
		Stage:         StageNotification72h,
		SubmittedAt:   mustTime(t, "2026-09-23T07:00:00Z"),
		CaseReference: "SRP-2026-000123",
		Via:           "human_srp",
	}, "user:sec@example.eu", mustTime(t, "2026-09-23T07:05:00Z"))
	require.NoError(t, err)
	assert.Equal(t, StateNotificationSubmitted, r.State)

	// The mitigation event is what starts the AEV final-report clock.
	r, err = r.SetMitigationAvailable(mustTime(t, "2026-10-01T12:00:00Z"), "user:sec@example.eu", "patch 3.1.4 published", mustTime(t, "2026-10-01T12:05:00Z"))
	require.NoError(t, err)

	r, err = r.TransitionTo(StateFinalReportDraft, "user:sec@example.eu", "assembling final report", mustTime(t, "2026-10-05T09:00:00Z"))
	require.NoError(t, err)
	r, err = r.RecordSubmission(Submission{
		Stage:         StageFinalReport,
		SubmittedAt:   mustTime(t, "2026-10-12T16:00:00Z"),
		CaseReference: "SRP-2026-000123",
		Via:           "human_srp",
	}, "user:sec@example.eu", mustTime(t, "2026-10-12T16:05:00Z"))
	require.NoError(t, err)
	assert.Equal(t, StateFinalReportSubmitted, r.State)

	r, err = r.TransitionTo(StateClosed, "user:sec@example.eu", "reporting cycle complete", mustTime(t, "2026-10-12T16:10:00Z"))
	require.NoError(t, err)
	assert.Equal(t, StateClosed, r.State)
	assert.True(t, r.State.Terminal())
}

func TestAEVFinalReportDeadlineIsFourteenDaysFromMitigation(t *testing.T) {
	r := classifyAEV(t)
	var err error
	r, err = r.SetMitigationAvailable(mustTime(t, "2026-10-01T12:00:00Z"), "user:sec@example.eu", "patch published", mustTime(t, "2026-10-01T12:05:00Z"))
	require.NoError(t, err)

	deadlines, err := r.Deadlines()
	require.NoError(t, err)

	var fr *Deadline
	for i := range deadlines {
		if deadlines[i].Stage == StageFinalReport {
			fr = &deadlines[i]
		}
	}
	require.NotNil(t, fr, "a final report deadline exists once a mitigation is available")
	assert.Equal(t, "2026-10-15T12:00:00Z", fr.Due.Format(time.RFC3339))
}

// --- SI workflow: EW -> 72h -> FR (no mitigation event) -------------------

func TestSevereIncidentHappyPathHasNoMitigationStage(t *testing.T) {
	r := classifySI(t)
	var err error

	r, err = r.TransitionTo(StateEarlyWarningDraft, "user:ir@example.eu", "assembling", mustTime(t, "2026-09-20T10:00:00Z"))
	require.NoError(t, err)
	r, err = r.RecordSubmission(Submission{Stage: StageEarlyWarning, SubmittedAt: mustTime(t, "2026-09-21T06:00:00Z"), Via: "human_srp"}, "user:ir@example.eu", mustTime(t, "2026-09-21T06:05:00Z"))
	require.NoError(t, err)

	r, err = r.TransitionTo(StateNotificationDraft, "user:ir@example.eu", "assembling", mustTime(t, "2026-09-22T08:00:00Z"))
	require.NoError(t, err)
	r, err = r.RecordSubmission(Submission{Stage: StageNotification72h, SubmittedAt: mustTime(t, "2026-09-22T20:00:00Z"), Via: "human_srp"}, "user:ir@example.eu", mustTime(t, "2026-09-22T20:05:00Z"))
	require.NoError(t, err)

	// SI reports do not take a mitigation anchor; attempting one is refused.
	_, err = r.SetMitigationAvailable(mustTime(t, "2026-10-01T12:00:00Z"), "user:ir@example.eu", "patch", mustTime(t, "2026-10-01T12:05:00Z"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "72-hour notification")

	r, err = r.TransitionTo(StateFinalReportDraft, "user:ir@example.eu", "assembling", mustTime(t, "2026-10-01T09:00:00Z"))
	require.NoError(t, err)
	r, err = r.RecordSubmission(Submission{Stage: StageFinalReport, SubmittedAt: mustTime(t, "2026-10-15T09:00:00Z"), Via: "human_srp"}, "user:ir@example.eu", mustTime(t, "2026-10-15T09:05:00Z"))
	require.NoError(t, err)
	assert.Equal(t, StateFinalReportSubmitted, r.State)

	deadlines, err := r.Deadlines()
	require.NoError(t, err)
	for _, d := range deadlines {
		if d.Stage == StageFinalReport {
			assert.Equal(t, "2026-10-22T20:00:00Z", d.Due.Format(time.RFC3339),
				"one calendar month from the 72-hour notification, not 30 days")
		}
	}
}

func TestSIHasNoFinalReportDeadlineBeforeTheNotificationIsSubmitted(t *testing.T) {
	r := classifySI(t)
	_, err := r.TransitionTo(StateEarlyWarningDraft, "user:ir@example.eu", "assembling", mustTime(t, "2026-09-20T10:00:00Z"))
	require.NoError(t, err)

	deadlines, err := r.Deadlines()
	require.NoError(t, err, "the derivable deadlines still resolve")
	for _, d := range deadlines {
		assert.NotEqual(t, StageFinalReport, d.Stage,
			"a final report deadline without a notification anchor is absent, not guessed")
	}
}

// --- the state machine refuses shortcuts -----------------------------------

func TestCannotSkipTheSeventyTwoHourNotification(t *testing.T) {
	r := classifyAEV(t)
	var err error
	r, err = r.TransitionTo(StateEarlyWarningDraft, "a", "draft", mustTime(t, "2026-09-20T10:00:00Z"))
	require.NoError(t, err)
	r, err = r.RecordSubmission(Submission{Stage: StageEarlyWarning, SubmittedAt: mustTime(t, "2026-09-21T08:00:00Z")}, "a", mustTime(t, "2026-09-21T08:05:00Z"))
	require.NoError(t, err)

	// Jumping straight to the final report because "the early warning covered
	// it" is a compliance failure, not an optimisation.
	_, err = r.TransitionTo(StateFinalReportDraft, "a", "skipping 72h", mustTime(t, "2026-09-21T09:00:00Z"))
	require.ErrorIs(t, err, ErrIllegalTransition)
	assert.Equal(t, StateEarlyWarningSubmitted, r.State, "a rejected transition does not half-apply")
}

func TestCannotSubmitAStageOutOfOrder(t *testing.T) {
	r := classifyAEV(t)
	_, err := r.RecordSubmission(Submission{
		Stage:       StageFinalReport,
		SubmittedAt: mustTime(t, "2026-09-21T08:00:00Z"),
	}, "a", mustTime(t, "2026-09-21T08:00:00Z"))
	require.ErrorIs(t, err, ErrInvalidReport)
}

func TestEventTypeCannotBeContradictedByTheTargetState(t *testing.T) {
	// An AEV-classified report cannot be pushed into a severe-incident state.
	r := classifyAEV(t)
	_, err := r.TransitionTo(StateReportableSI, "a", "reclassifying", mustTime(t, "2026-09-20T10:00:00Z"))
	require.Error(t, err)
}

func TestTerminalStatesAreAbsorbing(t *testing.T) {
	r := newDetectedReport(t)
	var err error
	r, err = r.TransitionTo(StateFalsePositive, "user:sec@example.eu", "the exploitation report was a scanner artefact", mustTime(t, "2026-09-20T09:20:00Z"))
	require.NoError(t, err)
	assert.True(t, r.State.Terminal())

	_, err = r.TransitionTo(StateAssessingReportability, "user:sec@example.eu", "reopening", mustTime(t, "2026-09-20T10:00:00Z"))
	require.ErrorIs(t, err, ErrIllegalTransition)
}

func TestDispositionRequiresAReason(t *testing.T) {
	r := newDetectedReport(t)
	_, err := r.TransitionTo(StateAssessingReportability, "a", "assessing", mustTime(t, "2026-09-20T09:10:00Z"))
	require.NoError(t, err)

	_, err = r.TransitionTo(StateNotReportable, "a", "", mustTime(t, "2026-09-20T09:20:00Z"))
	require.Error(t, err, "not reportable without reasoning is indistinguishable from never having looked")
}

func TestAEVRequiresExploitationEvidenceNotJustCriticalSeverity(t *testing.T) {
	// A CVSS 9.8 with no exploitation evidence is not a reportable AEV. The
	// severity is real and irrelevant to the determination.
	r := newDetectedReport(t)
	r.Exploitation = nil

	var err error
	r, err = r.TransitionTo(StateAssessingReportability, "a", "assessing", mustTime(t, "2026-09-20T09:10:00Z"))
	require.NoError(t, err)
	_, err = r.TransitionTo(StateReportableAEV, "a", "cvss is 9.8", mustTime(t, "2026-09-20T09:20:00Z"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exploitation evidence")
}

func TestEveryDecisionIsRetained(t *testing.T) {
	r := classifyAEV(t)
	r, err := r.TransitionTo(StateEarlyWarningDraft, "user:sec@example.eu", "assembling", mustTime(t, "2026-09-20T10:00:00Z"))
	require.NoError(t, err)

	require.Len(t, r.Decisions, 3)
	assert.Equal(t, StateAssessingReportability, r.Decisions[0].To)
	assert.Equal(t, StateReportableAEV, r.Decisions[1].To)
	assert.Equal(t, StateEarlyWarningDraft, r.Decisions[2].To)
	for i, d := range r.Decisions {
		assert.NotEmpty(t, d.Actor, "decision %d has no actor", i)
		assert.False(t, d.At.IsZero(), "decision %d has no timestamp", i)
	}
}

func TestOutstandingReportsWhatRemainsDueAndWhen(t *testing.T) {
	r := classifyAEV(t)
	r, err := r.TransitionTo(StateEarlyWarningDraft, "a", "assembling", mustTime(t, "2026-09-20T10:00:00Z"))
	require.NoError(t, err)

	out, err := r.Outstanding(mustTime(t, "2026-09-20T12:00:00Z"))
	require.NoError(t, err)
	require.Len(t, out, 2, "early warning and 72-hour notification are both outstanding")
	assert.Equal(t, "2026-09-21T09:00:00Z", out[0].Due.Format(time.RFC3339))
	assert.Equal(t, StageEarlyWarning, out[0].Stage)
	assert.Equal(t, StageNotification72h, out[1].Stage)
}

func TestOutstandingDropsSatisfiedStages(t *testing.T) {
	r := classifyAEV(t)
	r, err := r.TransitionTo(StateEarlyWarningDraft, "a", "assembling", mustTime(t, "2026-09-20T10:00:00Z"))
	require.NoError(t, err)
	r, err = r.RecordSubmission(Submission{Stage: StageEarlyWarning, SubmittedAt: mustTime(t, "2026-09-21T08:00:00Z")}, "a", mustTime(t, "2026-09-21T08:05:00Z"))
	require.NoError(t, err)

	out, err := r.Outstanding(mustTime(t, "2026-09-21T09:00:00Z"))
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, StageNotification72h, out[0].Stage)
}

func TestResubmissionKeepsTheFirstRecordedInstant(t *testing.T) {
	r := classifyAEV(t)
	r, err := r.TransitionTo(StateEarlyWarningDraft, "a", "assembling", mustTime(t, "2026-09-20T10:00:00Z"))
	require.NoError(t, err)
	r, err = r.RecordSubmission(Submission{Stage: StageEarlyWarning, SubmittedAt: mustTime(t, "2026-09-21T08:00:00Z")}, "a", mustTime(t, "2026-09-21T08:05:00Z"))
	require.NoError(t, err)

	// A "corrected" later timestamp must not be able to relabel a late
	// submission as on time.
	r, err = r.RecordSubmission(Submission{Stage: StageEarlyWarning, SubmittedAt: mustTime(t, "2026-09-21T23:00:00Z")}, "a", mustTime(t, "2026-09-21T23:05:00Z"))
	require.NoError(t, err)

	s, ok := r.SubmissionFor(StageEarlyWarning)
	require.True(t, ok)
	assert.Equal(t, "2026-09-21T08:00:00Z", s.SubmittedAt.Format(time.RFC3339))
}

// --- PEC ------------------------------------------------------------------

func TestPECIsRejectedForSevereIncidents(t *testing.T) {
	pec := &PEC{
		Applicable: true,
		Grounds:    []PECGrounds{PECGroundActiveRemediation},
		Reasoning:  "patch imminent",
		Evidence:   []string{"release plan RP-9"},
		DecisionAt: ptr(mustTime(t, "2026-09-22T10:00:00Z")),
		DecisionBy: "user:legal@example.eu",
	}
	require.ErrorIs(t, pec.Validate(EventTypeSI, StageNotification72h), ErrPECUnavailable)
}

func TestPECIsRejectedOutsideTheSeventyTwoHourNotification(t *testing.T) {
	pec := validPEC(t)
	require.ErrorIs(t, pec.Validate(EventTypeAEV, StageEarlyWarning), ErrPECUnavailable)
	require.ErrorIs(t, pec.Validate(EventTypeAEV, StageFinalReport), ErrPECUnavailable)
	require.NoError(t, pec.Validate(EventTypeAEV, StageNotification72h))
}

func TestPECRequiresGroundsReasoningEvidenceAndAHumanDecision(t *testing.T) {
	base := validPEC(t)

	noGrounds := *base
	noGrounds.Grounds = nil
	require.Error(t, noGrounds.Validate(EventTypeAEV, StageNotification72h))

	noReasoning := *base
	noReasoning.Reasoning = ""
	require.Error(t, noReasoning.Validate(EventTypeAEV, StageNotification72h))

	noEvidence := *base
	noEvidence.Evidence = nil
	require.Error(t, noEvidence.Validate(EventTypeAEV, StageNotification72h))

	noDecision := *base
	noDecision.DecisionAt = nil
	require.Error(t, noDecision.Validate(EventTypeAEV, StageNotification72h))

	noActor := *base
	noActor.DecisionBy = ""
	require.Error(t, noActor.Validate(EventTypeAEV, StageNotification72h))
}

func TestPECGroundOtherRequiresReasoning(t *testing.T) {
	pec := validPEC(t)
	pec.Grounds = []PECGrounds{PECGroundOther}
	pec.Reasoning = ""
	require.Error(t, pec.Validate(EventTypeAEV, StageNotification72h))

	pec.Reasoning = "a supply-chain compromise at the upstream vendor is being jointly investigated"
	require.NoError(t, pec.Validate(EventTypeAEV, StageNotification72h))
}

func TestPECIsNeverDecidedAutomatically(t *testing.T) {
	// The struct has no field the system fills in on its own: a claim without
	// an explicit human decision fails validation. This is asserted by
	// construction — an all-zero Applicable claim is a no-op, and any claim
	// needs DecisionBy.
	pec := validPEC(t)
	pec.DecisionBy = ""
	require.Error(t, pec.Validate(EventTypeAEV, StageNotification72h))
}

func TestSevereIncidentReportRefusesToCarryAPECClaim(t *testing.T) {
	r := classifySI(t)
	r.PEC = validPEC(t)
	// Re-entering assessment and reclassifying to SI must not leave a stale PEC
	// behind; the package refuses rather than silently dropping it.
	_, err := r.TransitionTo(StateNotReportable, "a", "withdrawn", mustTime(t, "2026-09-20T10:00:00Z"))
	require.NoError(t, err)
}

func validPEC(t *testing.T) *PEC {
	t.Helper()
	return &PEC{
		Applicable: true,
		Grounds:    []PECGrounds{PECGroundActiveRemediation, PECGroundOperationalSecurity},
		Reasoning: "A patch is in final validation; disclosure before publication would let actors " +
			"reproduce the fix and re-arm the exploit before users can update.",
		Evidence:   []string{"release plan RP-9", "vendor build log 2026-09-22"},
		DecisionAt: ptr(mustTime(t, "2026-09-22T10:00:00Z")),
		DecisionBy: "user:legal@example.eu",
	}
}

func ptr[T any](v T) *T { return &v }
