// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.

package cra

import (
	"fmt"
	"time"
)

// Anchors are the regulatory clock events a deadline can be measured from.
//
// The set is deliberately closed. Every entry corresponds to a fact ENISA or a
// competent authority may ask about. The things the previous implementation
// used — CVE publication time, feed ingestion time, scan time, ticket creation,
// assignment, triage acknowledgement, submission time — are absent because
// none of them is when the manufacturer became aware, and anchoring on them
// moves the deadline without any human deciding to move it.
type Anchors struct {
	// Awareness is the Article 14 anchor for the 24-hour and 72-hour stages.
	// Required for those two deadlines.
	Awareness Awareness

	// MitigationAvailableAt is the instant a corrective or mitigating measure
	// for the AEV became available. It anchors the AEV Final Report deadline.
	// Optional, but without it an AEV final-report deadline is undefined —
	// not "far in the future", undefined.
	//
	// This event matters on its own: the window does not start at awareness
	// because the manufacturer is not required to report a remediation that
	// does not yet exist.
	MitigationAvailableAt *time.Time

	// NotificationSubmittedAt is the instant the 72-hour Notification was
	// submitted. It anchors the severe-incident Final Report deadline.
	// Optional for the same reason as above.
	NotificationSubmittedAt *time.Time
}

// DeadlineAt computes the statutory deadline for a stage.
//
// The AEV and severe-incident final reports use *different anchors*:
//
//	AEV: mitigation_available_at + 14 days
//	SI:  notification_72h_submitted_at + 1 calendar month
//
// and both differ from the awareness-anchored 24h/72h stages. Conflating these
// into a single "SLA" — which is what the pre-2026 model did — cannot be made
// correct, because the three windows have three different starting events and
// one of them is a calendar-month arithmetic rather than a fixed duration.
//
// A calendar month is used for the severe-incident final report rather than 30
// days on purpose. A notification submitted on 31 January is due 28/29
// February; a 30-day rule would push it to 2 March, past the deadline. A
// notification on 31 August is due 30 September under both readings, which is
// exactly the kind of edge that only shows up in an audit.
func DeadlineAt(anchors Anchors, eventType EventType, stage Stage) (time.Time, error) {
	switch stage {
	case StageEarlyWarning:
		if err := anchors.Awareness.Validate(); err != nil {
			return time.Time{}, err
		}
		return anchors.Awareness.AwarenessAt.Add(EarlyWarningWindow), nil

	case StageNotification72h:
		if err := anchors.Awareness.Validate(); err != nil {
			return time.Time{}, err
		}
		return anchors.Awareness.AwarenessAt.Add(NotificationWindow), nil

	case StageFinalReport:
		switch eventType {
		case EventTypeAEV:
			if anchors.MitigationAvailableAt == nil {
				return time.Time{}, fmt.Errorf(
					"cra: AEV final report deadline is undefined: no corrective or mitigating measure has become available")
			}
			if anchors.MitigationAvailableAt.IsZero() {
				return time.Time{}, fmt.Errorf("cra: AEV mitigation_available_at is zero")
			}
			return anchors.MitigationAvailableAt.Add(AEVFinalReportWindow), nil

		case EventTypeSI:
			if anchors.NotificationSubmittedAt == nil {
				return time.Time{}, fmt.Errorf(
					"cra: severe incident final report deadline is undefined: the 72-hour notification has not been submitted")
			}
			if anchors.NotificationSubmittedAt.IsZero() {
				return time.Time{}, fmt.Errorf("cra: severe incident 72-hour notification timestamp is zero")
			}
			return addMonths(*anchors.NotificationSubmittedAt, SIFinalReportMonths), nil

		default:
			return time.Time{}, fmt.Errorf("cra: final report deadline requires an event type, got %q", eventType)
		}

	default:
		return time.Time{}, fmt.Errorf("cra: unknown stage %q", stage)
	}
}

// addMonths adds calendar months, clamping the day-of-month to the last day of
// the target month when the target month is shorter.
//
// The clamp is not cosmetic. time.Time.AddDate does not clamp: 31 January plus
// one month normalises to 3 March, which is *later* than the true deadline of
// 28 February. A deadline computed that way is a missed deadline reported as
// met, and it is the single most dangerous line in this file.
func addMonths(t time.Time, months int) time.Time {
	year, month, day := t.Date()

	total := int(month) - 1 + months
	year += total / 12
	m := total % 12
	if m < 0 {
		m += 12
		year--
	}
	target := time.Month(m + 1)

	// Day 0 of the following month is the last day of `target`.
	if last := time.Date(year, target+1, 0, 0, 0, 0, 0, t.Location()).Day(); day > last {
		day = last
	}
	return time.Date(year, target, day,
		t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), t.Location())
}

// Deadline is a computed statutory deadline with the provenance needed to
// explain it. Carrying the anchor and the rule alongside the instant is what
// lets the system answer "which deadline applies, and why that one?" without
// re-deriving it from mutable state later.
type Deadline struct {
	Stage     Stage     `json:"stage"`
	EventType EventType `json:"event_type"`
	Due       time.Time `json:"due"`
	// Anchor is the regulatory event the deadline is measured from.
	Anchor time.Time `json:"anchor"`
	// AnchorName identifies which event Anchor is, for human-readable
	// evidence output.
	AnchorName string `json:"anchor_name"`
	// Rule is a human-readable statement of the rule applied, suitable for
	// inclusion in an audit export.
	Rule string `json:"rule"`
}

// Anchor names.
const (
	AnchorAwareness           = "awareness_at"
	AnchorMitigationAvailable = "mitigation_available_at"
	AnchorNotificationSubmit  = "notification_72h_submitted_at"
)

// Deadline returns the Deadline for a stage together with its provenance.
func ComputeDeadline(anchors Anchors, eventType EventType, stage Stage) (Deadline, error) {
	due, err := DeadlineAt(anchors, eventType, stage)
	if err != nil {
		return Deadline{}, err
	}
	d := Deadline{Stage: stage, EventType: eventType, Due: due}
	switch stage {
	case StageEarlyWarning:
		d.Anchor = anchors.Awareness.AwarenessAt
		d.AnchorName = AnchorAwareness
		d.Rule = "Article 14: early warning within 24 hours of becoming aware"
	case StageNotification72h:
		d.Anchor = anchors.Awareness.AwarenessAt
		d.AnchorName = AnchorAwareness
		d.Rule = "Article 14: notification within 72 hours of becoming aware"
	case StageFinalReport:
		switch eventType {
		case EventTypeAEV:
			d.Anchor = *anchors.MitigationAvailableAt
			d.AnchorName = AnchorMitigationAvailable
			d.Rule = "Article 14: final report within 14 days of a corrective or mitigating measure becoming available"
		case EventTypeSI:
			d.Anchor = *anchors.NotificationSubmittedAt
			d.AnchorName = AnchorNotificationSubmit
			d.Rule = "Article 14: final report within one month of the 72-hour notification"
		}
	}
	return d, nil
}

// Status is the compliance state of a single stage deadline.
type Status string

const (
	// StatusPending — not yet due, not yet submitted.
	StatusPending Status = "pending"

	// StatusDue — within the final warning window (24h remaining) but not yet
	// submitted. Distinct from pending so an operator dashboard can surface
	// imminent deadlines without treating them as breaches.
	StatusDue Status = "due"

	// StatusSubmitted — submitted on time.
	StatusSubmitted Status = "submitted"

	// StatusLate — submitted after the deadline. Recorded distinctly from
	// submitted: a late submission is evidence of a missed requirement and
	// must remain visible in the audit chain.
	StatusLate Status = "late"

	// StatusMissed — the deadline passed with no submission.
	StatusMissed Status = "missed"

	// StatusNotApplicable — the stage does not apply to this event type.
	StatusNotApplicable Status = "not_applicable"
)

// DueWindow is how long before a deadline a stage becomes StatusDue. It is a
// Transparenz operational choice, not a regulatory threshold.
const DueWindow = 4 * time.Hour

// Evaluate classifies the state of a stage at a given instant.
//
// now and submittedAt are explicit parameters so the result is a pure function
// of its inputs and can be tested against DST transitions, leap days and month
// boundaries without touching the system clock.
func (d Deadline) Evaluate(now, submittedAt time.Time) Status {
	if submittedAt.IsZero() {
		if now.Before(d.Due) {
			if d.Due.Sub(now) <= DueWindow {
				return StatusDue
			}
			return StatusPending
		}
		return StatusMissed
	}
	if submittedAt.After(d.Due) {
		return StatusLate
	}
	return StatusSubmitted
}

// Overdue reports how far past the deadline `now` is. Zero when not overdue.
func (d Deadline) Overdue(now time.Time) time.Duration {
	if !now.After(d.Due) {
		return 0
	}
	return now.Sub(d.Due)
}

// Met reports whether the stage was submitted within its deadline. A stage that
// was never submitted is not met; callers that need to distinguish "late" from
// "missed" use Evaluate.
func (d Deadline) Met(submittedAt time.Time) bool {
	if submittedAt.IsZero() || submittedAt.After(d.Due) {
		return false
	}
	return true
}
