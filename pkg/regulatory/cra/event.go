// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.

package cra

import "errors"

// EventType is the CRA Article 14 reportable event class. Article 14 has two
// distinct reportable classes and they are not variants of one another: they
// differ in what ENISA asks for, in whether PEC is available, and — critically
// — in how the final report deadline is computed.
type EventType string

const (
	// EventTypeAEV is an Actively Exploited Vulnerability: a vulnerability
	// being exploited in the wild against a product with digital elements.
	EventTypeAEV EventType = "ACTIVELY_EXPLOITED_VULNERABILITY"

	// EventTypeSI is a Severe Incident: an incident affecting the security of
	// a product with digital elements. Root cause, incident nature and
	// mitigation dominate the required information.
	EventTypeSI EventType = "SEVERE_INCIDENT"
)

// Valid reports whether t is a known event type.
func (t EventType) Valid() bool {
	return t == EventTypeAEV || t == EventTypeSI
}

// String implements fmt.Stringer.
func (t EventType) String() string { return string(t) }

// SupportsPEC reports whether Particularly Exceptional Circumstances may be
// invoked for this event type.
//
// PEC applies *specifically* to the 72-hour notification of an AEV. It is not
// a generic CRA reporting exemption and it is not available to severe
// incidents. Encoding this here rather than in a validator means a severe
// incident cannot reach a PEC decision point at all.
func (t EventType) SupportsPEC() bool { return t == EventTypeAEV }

// State is a position in the Article 14 reporting lifecycle.
type State string

const (
	// StateDetected — an event has been identified but nothing has been
	// decided about it. No clock consequence.
	StateDetected State = "DETECTED"

	// StateAssessingReportability — the reportability determination is in
	// progress. This is where exploitation evidence, product applicability
	// and CRA scope are weighed. Still no clock consequence, but the 24-hour
	// window is running: awareness has happened, so a slow assessment is
	// already a missed deadline.
	StateAssessingReportability State = "ASSESSING_REPORTABILITY"

	// StateReportableAEV — determined reportable as an actively exploited
	// vulnerability.
	StateReportableAEV State = "REPORTABLE_AEV"

	// StateReportableSI — determined reportable as a severe incident.
	StateReportableSI State = "REPORTABLE_SI"

	// StateEarlyWarningDraft — the 24-hour Early Warning is being prepared.
	StateEarlyWarningDraft State = "EARLY_WARNING_DRAFT"

	// StateEarlyWarningSubmitted — the Early Warning has been submitted and
	// the case reference recorded.
	StateEarlyWarningSubmitted State = "EARLY_WARNING_SUBMITTED"

	// StateNotificationDraft — the 72-hour Notification is being prepared.
	StateNotificationDraft State = "NOTIFICATION_72H_DRAFT"

	// StateNotificationSubmitted — the 72-hour Notification has been submitted.
	StateNotificationSubmitted State = "NOTIFICATION_72H_SUBMITTED"

	// StateFinalReportDraft — the Final Report is being prepared.
	StateFinalReportDraft State = "FINAL_REPORT_DRAFT"

	// StateFinalReportSubmitted — the Final Report has been submitted.
	StateFinalReportSubmitted State = "FINAL_REPORT_SUBMITTED"

	// StateClosed — the reporting cycle is complete.
	StateClosed State = "CLOSED"

	// StateNotReportable — a positive determination that CRA Article 14 does
	// not apply, with reasoning. Distinct from the other exits because it is
	// a decision that must itself be evidenced.
	StateNotReportable State = "NOT_REPORTABLE"

	// StateFalsePositive — the event was not real.
	StateFalsePositive State = "FALSE_POSITIVE"

	// StateDuplicate — the event is already tracked by another reporting
	// record; this record is a duplicate.
	StateDuplicate State = "DUPLICATE"

	// StateUnderInvestigation — the reporting cycle is paused pending
	// further facts. The clocks do not stop.
	StateUnderInvestigation State = "UNDER_INVESTIGATION"
)

// Terminal reports whether no further transition is expected.
func (s State) Terminal() bool {
	switch s {
	case StateClosed, StateNotReportable, StateFalsePositive, StateDuplicate:
		return true
	}
	return false
}

// ReportabilityDetermined reports whether s is a state in which the
// reportability question has been answered yes.
func (s State) ReportabilityDetermined() bool {
	return s == StateReportableAEV || s == StateReportableSI
}

// Classified reports whether s is a disposition reached from assessment.
func (s State) Classified() bool {
	switch s {
	case StateReportableAEV, StateReportableSI, StateNotReportable,
		StateFalsePositive, StateDuplicate:
		return true
	}
	return false
}

// ErrIllegalTransition is returned when a transition is not permitted from the
// current state. The workflow is a regulatory object: skipping the 72-hour
// notification because the 24-hour early warning "covered it" is a compliance
// failure, not an optimisation.
var ErrIllegalTransition = errors.New("cra: illegal state transition")

// transitionTable is the explicit state machine. It is written out rather than
// derived so that every permitted edge is greppable and reviewable against the
// ENISA SRP workflow.
//
// Note the two exits from assessment that are *not* reportability decisions in
// the affirmative: StateDuplicate (another record already carries the duty) and
// StateUnderInvestigation (paused, clocks still running).
var transitionTable = map[State]map[State]bool{
	StateDetected: {
		StateAssessingReportability: true,
		StateFalsePositive:          true,
		StateDuplicate:              true,
	},
	StateAssessingReportability: {
		StateReportableAEV:      true,
		StateReportableSI:       true,
		StateNotReportable:      true,
		StateFalsePositive:      true,
		StateDuplicate:          true,
		StateUnderInvestigation: true,
	},
	StateUnderInvestigation: {
		StateAssessingReportability: true,
		StateReportableAEV:          true,
		StateReportableSI:           true,
		StateNotReportable:          true,
		StateFalsePositive:          true,
		StateDuplicate:              true,
	},
	StateReportableAEV: {
		StateEarlyWarningDraft:      true,
		StateAssessingReportability: true, // re-assessment may change the classification
		StateNotReportable:          true,
	},
	StateReportableSI: {
		StateEarlyWarningDraft:      true,
		StateAssessingReportability: true,
		StateNotReportable:          true,
	},
	StateEarlyWarningDraft: {
		StateEarlyWarningSubmitted:  true,
		StateAssessingReportability: true,
	},
	StateEarlyWarningSubmitted: {
		StateNotificationDraft: true,
	},
	StateNotificationDraft: {
		StateNotificationSubmitted: true,
		// A AEV may claim Particularly Exceptional Circumstances for the
		// 72-hour notification; the workflow does not change, the justification
		// does. Kept as a normal transition so the decision is recorded in the
		// audit chain even when submission proceeds.
		StateAssessingReportability: true,
	},
	StateNotificationSubmitted: {
		StateFinalReportDraft: true,
		// A severe incident may be reclassified to an AEV if investigation
		// shows the root cause is an actively exploited vulnerability. The
		// final-report deadline then changes rule, which is why this edge
		// exists and why DeadlineAt takes the event type per state.
		StateReportableAEV: true,
	},
	StateFinalReportDraft: {
		StateFinalReportSubmitted:   true,
		StateAssessingReportability: true,
	},
	StateFinalReportSubmitted: {
		StateClosed: true,
	},
	StateClosed: {},
	// Terminal dispositions are absorbing. Once a false positive is recorded
	// it cannot quietly become a reportable event; a genuine new event starts a
	// new record.
	StateNotReportable: {},
	StateFalsePositive: {},
	StateDuplicate:     {},
}

// CanTransition reports whether from -> to is permitted.
func CanTransition(from, to State) bool {
	if from == to {
		return false
	}
	return transitionTable[from][to]
}

// ErrStateMismatch is returned when a transition is legal in general but not
// from the reporting record's recorded event type — e.g. a severe incident
// being advanced toward a PEC claim.
var ErrStateMismatch = errors.New("cra: state is not valid for this event type")

// TransitionEventType returns the event type implied by a state, if the state
// pins one. States that are shared across both classes return ("", false).
func TransitionEventType(s State) (EventType, bool) {
	switch s {
	case StateReportableAEV:
		return EventTypeAEV, true
	case StateReportableSI:
		return EventTypeSI, true
	}
	return "", false
}

// ValidateTransition checks a proposed transition against both the state
// machine and the record's event class.
//
// The event-class check exists because the two classes have genuinely
// different rules downstream (PEC availability, final-report anchor). Letting a
// severe incident reach a state whose meaning depends on being an AEV would
// produce a deadline computed under the wrong rule.
func ValidateTransition(from, to State, eventType EventType) error {
	if !CanTransition(from, to) {
		return ErrIllegalTransition
	}
	if want, ok := TransitionEventType(to); ok && eventType.Valid() && want != eventType {
		return ErrStateMismatch
	}
	return nil
}

// Stage is a reporting milestone within the SRP workflow. Stages carry the
// submission semantics; States carry the lifecycle position.
type Stage string

const (
	// StageEarlyWarning is the 24-hour Early Warning.
	StageEarlyWarning Stage = "EARLY_WARNING"

	// StageNotification72h is the 72-hour Notification.
	StageNotification72h Stage = "NOTIFICATION_72H"

	// StageFinalReport is the Final Report.
	StageFinalReport Stage = "FINAL_REPORT"
)

// Valid reports whether s is a known stage.
func (s Stage) Valid() bool {
	switch s {
	case StageEarlyWarning, StageNotification72h, StageFinalReport:
		return true
	}
	return false
}

// String implements fmt.Stringer.
func (s Stage) String() string { return string(s) }
