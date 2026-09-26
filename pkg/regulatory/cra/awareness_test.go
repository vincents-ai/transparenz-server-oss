// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.

package cra

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	require.NoError(t, err)
	return v
}

func awareAt(t *testing.T, s string) Awareness {
	t.Helper()
	return Awareness{
		AwarenessAt: mustTime(t, s),
		Source:      AwarenessSourceIntelligence,
		Evidence:    "advisory snapshot ref adv-2026-0001",
	}
}

// compute wraps ComputeDeadline so the tests read as assertions about a
// deadline with its provenance rather than about a bare instant.
func compute(t *testing.T, a Anchors, et EventType, st Stage) Deadline {
	t.Helper()
	d, err := ComputeDeadline(a, et, st)
	require.NoError(t, err)
	return d
}

// --- P0: the clock runs from awareness, not from a feed timestamp -----------

func TestDeadlineRunsFromAwarenessNotFromCVSSOrFeedDate(t *testing.T) {
	// Awareness is deliberately placed at an instant unrelated to CVE
	// publication or KEV enrolment. Both of those were the anchors the
	// pre-2026 implementation used; if either reappears as the deadline
	// basis, this test fails.
	awareness := awareAt(t, "2026-09-20T09:00:00Z")

	ew := compute(t, Anchors{Awareness: awareness}, EventTypeAEV, StageEarlyWarning)
	assert.Equal(t, "2026-09-21T09:00:00Z", ew.Due.Format(time.RFC3339))
	assert.Equal(t, AnchorAwareness, ew.AnchorName)

	n72 := compute(t, Anchors{Awareness: awareness}, EventTypeAEV, StageNotification72h)
	assert.Equal(t, "2026-09-23T09:00:00Z", n72.Due.Format(time.RFC3339))
}

func TestDeadlineRefusesToFallBackWhenAwarenessIsMissing(t *testing.T) {
	// The whole defect: previously a missing anchor fell back to now+window.
	// The fallback is silent and always extends the deadline in the filer's
	// favour, so the package must refuse instead.
	_, err := DeadlineAt(Anchors{}, EventTypeAEV, StageEarlyWarning)
	require.ErrorIs(t, err, ErrNoAwareness)
}

func TestAwarenessRequiresEvidence(t *testing.T) {
	a := Awareness{AwarenessAt: time.Now(), Source: AwarenessSourceCERT}
	err := a.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "evidence")
}

func TestAwarenessRejectsUnknownSource(t *testing.T) {
	a := Awareness{AwarenessAt: time.Now(), Source: "a guess", Evidence: "x"}
	require.Error(t, a.Validate())
}

// --- P0-7: two different final-report deadline rules -----------------------

func TestAEVFinalReportRunsFromMitigationPlus14Days(t *testing.T) {
	awareness := awareAt(t, "2026-09-20T09:00:00Z")
	mitigation := mustTime(t, "2026-10-05T14:30:00Z")

	fr := compute(t, Anchors{
		Awareness:             awareness,
		MitigationAvailableAt: &mitigation,
	}, EventTypeAEV, StageFinalReport)

	assert.Equal(t, "2026-10-19T14:30:00Z", fr.Due.Format(time.RFC3339))
	assert.Equal(t, AnchorMitigationAvailable, fr.AnchorName)
	assert.Contains(t, fr.Rule, "14 days")
}

func TestAEVFinalReportIsUndefinedBeforeMitigationExists(t *testing.T) {
	awareness := awareAt(t, "2026-09-20T09:00:00Z")
	_, err := DeadlineAt(Anchors{Awareness: awareness}, EventTypeAEV, StageFinalReport)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mitigating measure")
}

func TestSevereIncidentFinalReportRunsFromNotificationPlusOneCalendarMonth(t *testing.T) {
	awareness := awareAt(t, "2026-09-20T09:00:00Z")
	notified := mustTime(t, "2026-09-23T11:00:00Z")

	fr := compute(t, Anchors{
		Awareness:               awareness,
		NotificationSubmittedAt: &notified,
	}, EventTypeSI, StageFinalReport)

	assert.Equal(t, "2026-10-23T11:00:00Z", fr.Due.Format(time.RFC3339))
	assert.Equal(t, AnchorNotificationSubmit, fr.AnchorName)
	assert.Contains(t, fr.Rule, "one month")
}

func TestSevereIncidentFinalReportIsUndefinedBeforeNotification(t *testing.T) {
	awareness := awareAt(t, "2026-09-20T09:00:00Z")
	_, err := DeadlineAt(Anchors{Awareness: awareness}, EventTypeSI, StageFinalReport)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "72-hour notification has not been submitted")
}

func TestTheTwoFinalReportRulesGenuinelyDiffer(t *testing.T) {
	// Same anchors, same event, different class, different due date. This is
	// the test that could not have passed against a single generic "SLA".
	awareness := awareAt(t, "2026-09-20T09:00:00Z")
	notified := mustTime(t, "2026-09-23T11:00:00Z")
	mitigation := mustTime(t, "2026-09-25T08:00:00Z")

	aev := compute(t, Anchors{
		Awareness: awareness, MitigationAvailableAt: &mitigation,
	}, EventTypeAEV, StageFinalReport)

	si := compute(t, Anchors{
		Awareness: awareness, NotificationSubmittedAt: &notified,
	}, EventTypeSI, StageFinalReport)

	assert.NotEqual(t, aev.Due, si.Due)
	assert.Equal(t, "2026-10-09T08:00:00Z", aev.Due.Format(time.RFC3339))
	assert.Equal(t, "2026-10-23T11:00:00Z", si.Due.Format(time.RFC3339))
}

// --- calendar-month arithmetic: the edge cases that decide compliance ------

func TestOneMonthIsACalendarMonthNotThirtyDays(t *testing.T) {
	cases := []struct {
		name      string
		submitted string
		want      string
	}{
		// 30-day arithmetic would give 2 March and breach the deadline.
		{"short month clamps to last day of February (non-leap)", "2027-01-31T10:00:00Z", "2027-02-28T10:00:00Z"},
		{"short month clamps in a leap year", "2028-01-31T10:00:00Z", "2028-02-29T10:00:00Z"},
		// 30-day arithmetic would give 30 September; the true deadline is earlier.
		{"31-day month preserves the day", "2027-08-31T10:00:00Z", "2027-09-30T10:00:00Z"},
		{"month boundary", "2027-02-28T23:59:59Z", "2027-03-28T23:59:59Z"},
		{"year boundary", "2026-12-31T00:00:00Z", "2027-01-31T00:00:00Z"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			submitted := mustTime(t, tc.submitted)
			got := compute(t, Anchors{NotificationSubmittedAt: &submitted}, EventTypeSI, StageFinalReport)
			assert.Equal(t, tc.want, got.Due.Format(time.RFC3339))
		})
	}
}

func TestThirtyDayArithmeticWouldHaveBreachedTheDeadline(t *testing.T) {
	// States the reason the calendar-month rule exists, as an executable claim.
	submitted := mustTime(t, "2027-01-31T10:00:00Z")
	got := compute(t, Anchors{NotificationSubmittedAt: &submitted}, EventTypeSI, StageFinalReport)

	thirtyDays := submitted.Add(30 * 24 * time.Hour)
	assert.True(t, thirtyDays.After(got.Due),
		"a 30-day window would land %s, after the true deadline %s",
		thirtyDays.Format(time.RFC3339), got.Due.Format(time.RFC3339))
}

func TestTwentyFourAndSeventyTwoHoursAreAbsoluteDurations(t *testing.T) {
	// A DST transition must not lengthen or shorten a 24-hour regulatory
	// window. The window is a duration against an instant, so it is immune —
	// but assert it, because wall-clock arithmetic is exactly the bug this guards.
	loc, err := time.LoadLocation("Europe/Berlin")
	require.NoError(t, err)

	// 2026-10-25 is the European end-of-summer-time transition.
	before := time.Date(2026, 10, 24, 23, 0, 0, 0, loc)
	awareness := Awareness{
		AwarenessAt: before, Source: AwarenessSourceCERT, Evidence: "cert mail",
	}
	ew := compute(t, Anchors{Awareness: awareness}, EventTypeAEV, StageEarlyWarning)

	assert.Equal(t, 24*time.Hour, ew.Due.Sub(before))
	// 24h of absolute time lands at 22:00 CET — an hour earlier on the wall
	// clock than naive wall-clock arithmetic would produce, and exactly 24h
	// after awareness.
	assert.Equal(t, "2026-10-25T22:00:00+01:00", ew.Due.Format(time.RFC3339))

	n72 := compute(t, Anchors{Awareness: awareness}, EventTypeAEV, StageNotification72h)
	assert.Equal(t, 72*time.Hour, n72.Due.Sub(before))
}

func TestAwarenessAndDeadlineAreComparedInAbsoluteTimeAcrossZones(t *testing.T) {
	utc := mustTime(t, "2026-09-20T09:00:00Z")
	tokyo := utc.In(time.FixedZone("JST", 9*60*60))

	dUTC := compute(t, Anchors{Awareness: Awareness{
		AwarenessAt: utc, Source: AwarenessSourceCERT, Evidence: "cert mail",
	}}, EventTypeAEV, StageEarlyWarning)

	dTokyo := compute(t, Anchors{Awareness: Awareness{
		AwarenessAt: tokyo, Source: AwarenessSourceCERT, Evidence: "cert mail",
	}}, EventTypeAEV, StageEarlyWarning)

	assert.True(t, dUTC.Due.Equal(dTokyo.Due))
}

// --- late discovery and corrected awareness -------------------------------

func TestLateDiscoveryStillProducesTheFullWindow(t *testing.T) {
	// Awareness in the past is not "clamped to now". A manufacturer who
	// becomes aware late still has 24 hours from when it became aware, and a
	// missed deadline is a fact to record — not something to hide by moving the
	// anchor forward.
	late := awareAt(t, "2026-01-02T03:00:00Z")
	d := compute(t, Anchors{Awareness: late}, EventTypeAEV, StageEarlyWarning)
	assert.Equal(t, "2026-01-03T03:00:00Z", d.Due.Format(time.RFC3339))
	assert.Equal(t, StatusMissed, d.Evaluate(mustTime(t, "2026-02-01T00:00:00Z"), time.Time{}))
}

func TestAwarenessCorrectionIsAuditedAndRequiresReason(t *testing.T) {
	original := awareAt(t, "2026-09-20T09:00:00Z")

	_, _, err := ApplyAwarenessCorrection(original, AwarenessCorrection{
		NewValue: mustTime(t, "2026-09-20T05:00:00Z"),
		// no reason, no evidence, no actor
	})
	require.Error(t, err)

	updated, entry, err := ApplyAwarenessCorrection(original, AwarenessCorrection{
		NewValue: mustTime(t, "2026-09-20T05:00:00Z"),
		Reason:   "advisory timestamp was the sender's clock; our mail gateway logged receipt at 05:00Z",
		Evidence: "gateway log export gl-2026-09-20",
		Actor:    "user:sec-lead@example.eu",
		At:       mustTime(t, "2026-09-21T10:00:00Z"),
	})
	require.NoError(t, err)

	assert.Equal(t, "2026-09-20T05:00:00Z", updated.AwarenessAt.Format(time.RFC3339))
	assert.True(t, entry.IsCorrection())
	assert.Equal(t, "user:sec-lead@example.eu", entry.Actor)
	assert.Equal(t, "2026-09-20T09:00:00Z", entry.OldValue.Format(time.RFC3339))
	assert.Equal(t, "2026-09-20T05:00:00Z", entry.NewValue.Format(time.RFC3339))
	assert.NotEmpty(t, entry.Reason)
	assert.NotEmpty(t, entry.EvidenceReference)
}

func TestCorrectingAwarenessMovesDeadlinesButNotAlreadyRecordedSubmissions(t *testing.T) {
	// The point of the audit chain: a correction may change the anchor, but the
	// recorded submission instant is a fact and the variance stays visible.
	original := awareAt(t, "2026-09-20T09:00:00Z")
	submitted := mustTime(t, "2026-09-21T08:00:00Z")

	before := compute(t, Anchors{Awareness: original}, EventTypeAEV, StageEarlyWarning)
	assert.True(t, before.Met(submitted))

	corrected, _, err := ApplyAwarenessCorrection(original, AwarenessCorrection{
		NewValue: mustTime(t, "2026-09-20T04:00:00Z"),
		Reason:   "advisory timestamp was the sender's clock; our gateway logged receipt at 04:00Z",
		Evidence: "ticket TS-4417",
		Actor:    "user:sec-lead@example.eu",
	})
	require.NoError(t, err)

	after := compute(t, Anchors{Awareness: corrected}, EventTypeAEV, StageEarlyWarning)
	assert.Equal(t, StatusLate, after.Evaluate(submitted.Add(time.Hour), submitted),
		"the corrected anchor exposes that the submission was in fact late")
}

func TestCorrectionThatChangesNothingIsRejected(t *testing.T) {
	original := awareAt(t, "2026-09-20T09:00:00Z")
	_, _, err := ApplyAwarenessCorrection(original, AwarenessCorrection{
		NewValue: original.AwarenessAt,
		Reason:   "no change", Evidence: "x", Actor: "y",
	})
	require.Error(t, err)
}

// --- deadline status evaluation -------------------------------------------

func TestEvaluateDistinguishesPendingDueSubmittedLateAndMissed(t *testing.T) {
	d := compute(t, Anchors{Awareness: awareAt(t, "2026-09-20T09:00:00Z")},
		EventTypeAEV, StageEarlyWarning)
	due := d.Due

	assert.Equal(t, StatusPending, d.Evaluate(due.Add(-48*time.Hour), time.Time{}))
	assert.Equal(t, StatusDue, d.Evaluate(due.Add(-time.Hour), time.Time{}))
	assert.Equal(t, StatusMissed, d.Evaluate(due.Add(time.Minute), time.Time{}))
	assert.Equal(t, StatusSubmitted, d.Evaluate(due.Add(-time.Minute), due.Add(-time.Minute)))
	assert.Equal(t, StatusLate, d.Evaluate(due, due.Add(time.Second)))
}

func TestLateSubmissionIsNotReportedAsMet(t *testing.T) {
	// A late submission is evidence of a missed requirement and must never be
	// collapsed into "submitted".
	d := compute(t, Anchors{Awareness: awareAt(t, "2026-09-20T09:00:00Z")},
		EventTypeAEV, StageEarlyWarning)
	assert.False(t, d.Met(d.Due.Add(time.Second)))
	assert.False(t, d.Met(time.Time{}), "never submitted is not met")
}
