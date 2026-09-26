// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.

package cra

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Report is the regulatory object: a single CRA Article 14 reporting cycle for
// one reportable event.
//
// This is intentionally *not* "a vulnerability with a deadline attached". The
// distinction is the whole point of Article 14: the duty attaches to an event
// (an actively exploited vulnerability, or a severe incident) that may be
// reached through a vulnerability, and a vulnerability may spawn several
// independent reports — one per affected product line, one per third-party
// component exposure — each with its own clock.
type Report struct {
	ID    uuid.UUID `json:"id"`
	OrgID uuid.UUID `json:"org_id"`

	// EventType is the reportable class. Required before a report can leave
	// assessment; it drives the final-report deadline rule and PEC
	// availability, so it is never inferred downstream.
	EventType EventType `json:"event_type"`

	State State `json:"state"`

	// Awareness is the clock anchor and its provenance. Required for the 24h
	// and 72h deadlines.
	Awareness Awareness `json:"awareness"`

	// VulnerabilityID is the CVE for an AEV report. Empty for a severe
	// incident whose cause is not a tracked vulnerability.
	VulnerabilityID string `json:"vulnerability_id,omitempty"`

	// ProductID identifies the product with digital elements the obligation is
	// owed in respect of.
	//
	// This is not decoration. Article 14 attaches the duty to the *product*,
	// not to the upstream component and not to the CVE: nobody reports a
	// library. A report that does not name its product cannot answer "which
	// product is affected?", which is the first question an authority asks and
	// one a product with a hundred SBOMs needs answered precisely.
	ProductID   string     `json:"product_id,omitempty"`
	ProductName string     `json:"product_name,omitempty"`
	SbomID      *uuid.UUID `json:"sbom_id,omitempty"`

	// The third-party component through which the vulnerability reached the
	// product, when it arrived by that route.
	ComponentName    string `json:"component_name,omitempty"`
	ComponentVersion string `json:"component_version,omitempty"`
	ComponentPURL    string `json:"component_purl,omitempty"`

	// EUVDID is the ENISA EUVD identifier, when one is assigned. Distinct
	// from the CVE: ENISA's own record is what ENISA's SRP form references.
	EUVDID string `json:"euvd_id,omitempty"`

	// Title and Description are the human summary of what happened.
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`

	// Exploitation is the evidence that the vulnerability is being exploited
	// in the wild. Its presence is what makes a vulnerability reportable —
	// the CVSS score is not consulted, and never was a substitute.
	//
	// Required when EventType is EventTypeAEV.
	Exploitation *ExploitationEvidence `json:"exploitation,omitempty"`

	// MitigationAvailableAt mirrors Anchors.MitigationAvailableAt on the
	// report so the AEV final-report deadline is derivable from the report
	// alone.
	MitigationAvailableAt *time.Time `json:"mitigation_available_at,omitempty"`

	// PEC records any Particularly Exceptional Circumstances claim. Only
	// meaningful for an AEV's 72-hour notification; nil otherwise.
	PEC *PEC `json:"pec,omitempty"`

	// Coordinator identifies the CSIRT designated as coordinator (CDaC) the
	// report is addressed to.
	Coordinator *Coordinator `json:"coordinator,omitempty"`

	// Submissions records what has actually been submitted and when, per
	// stage. Recording the *actual* submission instant is what allows the
	// final-report deadline for a severe incident to be computed, and what
	// proves a deadline was met.
	Submissions []Submission `json:"submissions,omitempty"`

	// DispositionReason explains a non-reportable exit. Required for
	// NOT_REPORTABLE, FALSE_POSITIVE and DUPLICATE.
	DispositionReason string `json:"disposition_reason,omitempty"`

	// DuplicateOf references the report that already carries this duty, for
	// StateDuplicate.
	DuplicateOf *uuid.UUID `json:"duplicate_of,omitempty"`

	// Decisions is the ordered decision log — every classification and
	// transition with its supporting facts. This is the answer to "why is or
	// isn't this reportable?" and it is retained, not recomputed.
	Decisions []Decision `json:"decisions,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ExploitationEvidence is the factual basis for treating a vulnerability as
// actively exploited. ENISA's AEV data model expects exploitation information,
// and a report asserting exploitation without any is asserting something the
// manufacturer cannot demonstrate.
type ExploitationEvidence struct {
	// ObservedAt is when exploitation was first observed.
	ObservedAt time.Time `json:"observed_at"`

	// Summary describes what was observed.
	Summary string `json:"summary"`

	// Source is the provenance class of the exploitation evidence.
	Source AwarenessSource `json:"source"`

	// Reference points at the durable artefact (capture, advisory, feed
	// record, incident ticket).
	Reference string `json:"reference"`

	// AttackVector is the observed vector (network, physical, local, social).
	AttackVector string `json:"attack_vector,omitempty"`

	// AttributedActor is the malicious actor, where known. ENISA expects this
	// "where available" — it is frequently unknown early, and guessing it is
	// worse than leaving it blank.
	AttributedActor string `json:"attributed_actor,omitempty"`

	// Scope is the observed exploitation scope (e.g. which products, which
	// versions, how many victims observed).
	Scope string `json:"scope,omitempty"`
}

// Validate reports whether the exploitation evidence is fit to support an AEV
// determination.
func (e *ExploitationEvidence) Validate() error {
	if e == nil {
		return errors.New("cra: actively exploited vulnerability reports require exploitation evidence")
	}
	if e.ObservedAt.IsZero() {
		return errors.New("cra: exploitation evidence requires an observation time")
	}
	if !e.Source.Valid() {
		return fmt.Errorf("cra: exploitation evidence source %q is not a known source", e.Source)
	}
	if e.Reference == "" {
		return errors.New("cra: exploitation evidence requires a reference to the observed artefact")
	}
	if e.Summary == "" {
		return errors.New("cra: exploitation evidence requires a summary of what was observed")
	}
	return nil
}

// Submission records an actual submission of a stage.
type Submission struct {
	Stage Stage `json:"stage"`

	// SubmittedAt is the real submission instant. This is a fact, not a
	// derived value, and it is the anchor for the severe-incident final-report
	// deadline.
	SubmittedAt time.Time `json:"submitted_at"`

	// CaseReference is the identifier the receiving authority returned.
	CaseReference string `json:"case_reference,omitempty"`

	// PackageDigest is the SHA-256 of the validated submission package that
	// was actually sent. Ties the record to an exact byte sequence, so the
	// evidence cannot drift after the fact.
	PackageDigest string `json:"package_digest,omitempty"`

	// SubmittedBy is the principal that made the submission.
	SubmittedBy string `json:"submitted_by,omitempty"`

	// Via records the transport used. "human_srp" is the expected value today:
	// the ENISA SRP has no API, so a submission is performed by a person in
	// the SRP interface and recorded here. See pkg/regulatory/srp.
	Via string `json:"via,omitempty"`
}

// SubmissionFor returns the submission recorded for a stage.
func (r *Report) SubmissionFor(stage Stage) (Submission, bool) {
	for _, s := range r.Submissions {
		if s.Stage == stage {
			return s, true
		}
	}
	return Submission{}, false
}

// Decision is one entry in the retained decision log.
type Decision struct {
	At       time.Time `json:"at"`
	From     State     `json:"from,omitempty"`
	To       State     `json:"to"`
	Actor    string    `json:"actor"`
	Reason   string    `json:"reason,omitempty"`
	Evidence []string  `json:"evidence,omitempty"`
}

// ErrInvalidReport is returned when a report cannot legally change state.
var ErrInvalidReport = errors.New("cra: report is not in a state that permits this change")

// TransitionTo validates and applies a state transition, appending the decision
// to the retained log.
//
// A transition that fails validation leaves the report untouched. This is a
// value method returning a new report rather than a pointer method mutating in
// place, so a rejected transition cannot half-apply: there is no window in
// which the state advanced but the decision log did not.
func (r Report) TransitionTo(to State, actor, reason string, now time.Time) (Report, error) {
	if now.IsZero() {
		now = time.Now()
	}
	if err := ValidateTransition(r.State, to, r.EventType); err != nil {
		return r, fmt.Errorf("%w: %s -> %s: %w", ErrInvalidReport, r.State, to, err)
	}
	// Leaving a non-reportable state for a reportable one requires exploitation
	// evidence to exist, whatever the current state says. A report that claims
	// active exploitation without an artefact is not defensible.
	if to.ReportabilityDetermined() && to == StateReportableAEV {
		if err := r.Exploitation.Validate(); err != nil {
			return r, fmt.Errorf("%w: %s -> %s: %w", ErrInvalidReport, r.State, to, err)
		}
	}
	// Exiting into a disposition requires a stated reason. "Not reportable" with
	// no reasoning is indistinguishable from "we never looked".
	if to.Classified() && to != StateReportableAEV && to != StateReportableSI {
		if reason == "" {
			return r, fmt.Errorf("%w: %s requires a stated reason", ErrInvalidReport, to)
		}
	}
	// A severe incident cannot carry a PEC claim: it is not available to it.
	if to == StateReportableSI && r.PEC != nil {
		return r, fmt.Errorf("%w: particularly exceptional circumstances do not apply to severe incidents", ErrInvalidReport)
	}

	from := r.State
	r.State = to
	// The event type is a property of the *report*, not of the current state.
	// Only the two classification states pin it; every other state inherits
	// the determination already made. Clearing it here would make the AEV/SI
	// final-report rule unresolvable the moment the workflow moved past
	// assessment — which is most of the workflow.
	if pinned, ok := TransitionEventType(to); ok {
		r.EventType = pinned
	}
	if reason != "" {
		r.DispositionReason = reason
	}
	if now.After(r.UpdatedAt) {
		r.UpdatedAt = now
	}
	r.Decisions = append(r.Decisions, Decision{
		At:     now,
		From:   from,
		To:     to,
		Actor:  actor,
		Reason: reason,
	})
	return r, nil
}

// Anchors projects the report into the deadline anchor set.
func (r *Report) Anchors() Anchors {
	a := Anchors{
		Awareness:             r.Awareness,
		MitigationAvailableAt: r.MitigationAvailableAt,
	}
	if s, ok := r.SubmissionFor(StageNotification72h); ok && !s.SubmittedAt.IsZero() {
		t := s.SubmittedAt
		a.NotificationSubmittedAt = &t
	}
	return a
}

// Deadlines computes every deadline that is currently derivable.
//
// Absent anchors produce absent deadlines rather than substituted ones. A
// caller wanting to know "what is outstanding?" should use Outstanding.
func (r *Report) Deadlines() ([]Deadline, error) {
	if !r.EventType.Valid() {
		return nil, fmt.Errorf("cra: report %s has no determined event type (state %s)", r.ID, r.State)
	}
	anchors := r.Anchors()
	var out []Deadline
	for _, stage := range []Stage{StageEarlyWarning, StageNotification72h, StageFinalReport} {
		d, err := ComputeDeadline(anchors, r.EventType, stage)
		if err != nil {
			// An undefined final-report deadline is expected before the
			// mitigation (AEV) or notification (SI) anchor exists. It is not
			// an error condition for the other two stages, which must resolve.
			if stage == StageFinalReport {
				continue
			}
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

// OutstandingStage is a stage that has a deadline, is not yet satisfied, and is
// how the system answers "what remains due and when?".
type OutstandingStage struct {
	Deadline
	Status Status
}

// Outstanding returns the stages that still require action at `now`.
func (r *Report) Outstanding(now time.Time) ([]OutstandingStage, error) {
	deadlines, err := r.Deadlines()
	if err != nil {
		return nil, err
	}
	var out []OutstandingStage
	for _, d := range deadlines {
		s, ok := r.SubmissionFor(d.Stage)
		var submittedAt time.Time
		if ok {
			submittedAt = s.SubmittedAt
		}
		status := d.Evaluate(now, submittedAt)
		if status == StatusSubmitted || status == StatusLate {
			continue
		}
		out = append(out, OutstandingStage{Deadline: d, Status: status})
	}
	return out, nil
}

// RecordSubmission appends a stage submission and advances the workflow.
//
// The state advance is computed rather than supplied, so a caller cannot submit
// a Final Report without the preceding stages having been recorded. Submission
// timestamps are facts: they are not overwritten if a stage is re-submitted,
// because the original instant is the one the deadline is measured against.
func (r Report) RecordSubmission(s Submission, actor string, now time.Time) (Report, error) {
	if !s.Stage.Valid() {
		return r, fmt.Errorf("cra: unknown stage %q", s.Stage)
	}
	if s.SubmittedAt.IsZero() {
		return r, fmt.Errorf("cra: submission for %s requires a submission time", s.Stage)
	}
	if !r.State.ReportabilityDetermined() && !r.inReportingStages() {
		return r, fmt.Errorf("%w: cannot submit %s from state %s", ErrInvalidReport, s.Stage, r.State)
	}
	next, err := r.stageStateFor(s.Stage)
	if err != nil {
		return r, err
	}
	_, alreadySubmitted := r.SubmissionFor(s.Stage)

	if alreadySubmitted {
		// Re-submission: keep the first recorded instant. The deadline runs
		// from what actually happened first, and a later "corrected" timestamp
		// is exactly the thing that would let a missed deadline be relabelled
		// as met.
		for i := range r.Submissions {
			if r.Submissions[i].Stage == s.Stage {
				r.Submissions[i].CaseReference = s.CaseReference
				r.Submissions[i].PackageDigest = s.PackageDigest
				r.Submissions[i].Via = s.Via
			}
		}
	} else {
		if s.SubmittedBy == "" {
			s.SubmittedBy = actor
		}
		r.Submissions = append(r.Submissions, s)
	}
	// A re-submission corrects the reference but does not re-advance the
	// workflow: the state is already the stage's submitted state.
	if alreadySubmitted {
		if now.IsZero() {
			now = time.Now()
		}
		if now.After(r.UpdatedAt) {
			r.UpdatedAt = now
		}
		return r, nil
	}

	// Filing a submission implies the draft was produced, but the draft is a
	// distinct fact with a distinct actor and time, and the state machine
	// refuses to jump from a classification straight to a submitted stage. The
	// step is inserted here rather than pushed onto the caller, because
	// remembering to take it is exactly the kind of ceremony that gets skipped
	// under a 24-hour clock — and a skipped draft step leaves a hole in the
	// audit trail of who prepared the filing.
	if r.State.ReportabilityDetermined() {
		draft, err := draftStateFor(s.Stage)
		if err != nil {
			return r, err
		}
		drafted, err := r.TransitionTo(draft, actor, "drafting "+s.Stage.String(), now)
		if err != nil {
			return r, err
		}
		r = drafted
	}

	r, err = r.TransitionTo(next, actor, "stage submitted: "+s.Stage.String(), now)
	if err != nil {
		return r, err
	}
	return r, nil
}

// draftStateFor is the drafting state preceding a stage's submitted state.
func draftStateFor(stage Stage) (State, error) {
	switch stage {
	case StageEarlyWarning:
		return StateEarlyWarningDraft, nil
	case StageNotification72h:
		return StateNotificationDraft, nil
	case StageFinalReport:
		return StateFinalReportDraft, nil
	}
	return "", fmt.Errorf("cra: unknown stage %q", stage)
}

func (r *Report) inReportingStages() bool {
	switch r.State {
	case StateEarlyWarningDraft, StateEarlyWarningSubmitted,
		StateNotificationDraft, StateNotificationSubmitted,
		StateFinalReportDraft:
		return true
	}
	return false
}

func (r *Report) stageStateFor(stage Stage) (State, error) {
	switch stage {
	case StageEarlyWarning:
		return StateEarlyWarningSubmitted, nil
	case StageNotification72h:
		return StateNotificationSubmitted, nil
	case StageFinalReport:
		return StateFinalReportSubmitted, nil
	}
	return "", fmt.Errorf("cra: unknown stage %q", stage)
}
