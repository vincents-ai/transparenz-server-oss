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
)

// PECGrounds is a documented ground on which dissemination delay may be
// requested for the 72-hour notification of an actively exploited
// vulnerability.
//
// The grounds are named, not free-text. A claim of "exceptional
// circumstances" with no ground selected cannot be reviewed, and an
// un-reviewable claim is one an authority will simply disregard.
type PECGrounds string

const (
	// PECGroundActiveRemediation — a corrective or mitigating measure is
	// imminent and disclosure before it lands would negate its effect.
	PECGroundActiveRemediation PECGrounds = "active_remediation"

	// PECGroundOperationalSecurity — disclosure would reveal defensive
	// posture or detection capability in a way that materially increases harm
	// to users.
	PECGroundOperationalSecurity PECGrounds = "operational_security"

	// PECGroundLawEnforcement — law-enforcement or judicial proceedings
	// require the timing to differ.
	PECGroundLawEnforcement PECGrounds = "law_enforcement"

	// PECGroundPersonalData — the information would require disclosure of
	// personal data whose protection outweighs the timing.
	PECGroundPersonalData PECGrounds = "personal_data"

	// PECGroundOther — a ground ENISA's criteria do not name. Requires
	// reasoning and evidence, as does every ground, but carries the
	// additional expectation of explaining why none of the named grounds
	// applied.
	PECGroundOther PECGrounds = "other"
)

// Valid reports whether g is a known ground.
func (g PECGrounds) Valid() bool {
	switch g {
	case PECGroundActiveRemediation, PECGroundOperationalSecurity,
		PECGroundLawEnforcement, PECGroundPersonalData, PECGroundOther:
		return true
	}
	return false
}

// PEC is a Particularly Exceptional Circumstances claim.
//
// PEC is narrow. It attaches to the 72-hour notification of an AEV and to
// nothing else: not to the early warning, not to the final report, and not to
// severe incidents at all. The temptation to model it as a generic "reporting
// extension" is what makes it dangerous, because a generic extension would
// silently apply to stages ENISA never contemplated.
//
// A PEC claim is also never automatic. Nothing in this package decides that
// the circumstances are exceptional — that determination is legal, contextual
// and case-specific. What this package does is refuse to accept a claim that
// lacks grounds, reasoning or evidence, and refuse to attach one to the wrong
// event class.
type PEC struct {
	// Applicable reports whether a PEC claim is being made at all.
	Applicable bool `json:"applicable"`

	// Grounds are the selected grounds. At least one required when
	// Applicable.
	Grounds []PECGrounds `json:"grounds,omitempty"`

	// Reasoning is the justification. Required.
	Reasoning string `json:"reasoning,omitempty"`

	// Evidence supports the claim. At least one required.
	Evidence []string `json:"evidence,omitempty"`

	// DisseminationDelayRequested is the delay the filer is asking ENISA to
	// permit. Optional — a claim can be recorded without a specific request.
	DisseminationDelayRequested *time.Duration `json:"dissemination_delay_requested,omitempty"`

	// DecisionAt is when a human decided the claim, and DecisionBy is who.
	// Both required: the claim is a human or legal decision, not a system
	// inference.
	DecisionAt *time.Time `json:"decision_at,omitempty"`
	DecisionBy string     `json:"decision_by,omitempty"`
}

// ErrPECUnavailable is returned when PEC is claimed where it does not apply.
var ErrPECUnavailable = errors.New("cra: particularly exceptional circumstances are not available here")

// Validate checks a PEC claim against its event type and stage.
//
// The two error cases are the two ways a PEC claim goes wrong in practice:
// claiming it for a severe incident, and claiming it without the substance
// (grounds, reasoning, evidence) that would make it reviewable.
func (p *PEC) Validate(eventType EventType, stage Stage) error {
	if p == nil || !p.Applicable {
		return nil
	}
	if !eventType.SupportsPEC() {
		return fmt.Errorf("%w: not available for %s", ErrPECUnavailable, eventType)
	}
	if stage != StageNotification72h {
		return fmt.Errorf("%w: only available for the 72-hour notification, got %s", ErrPECUnavailable, stage)
	}
	if len(p.Grounds) == 0 {
		return errors.New("cra: a PEC claim requires at least one ground")
	}
	for _, g := range p.Grounds {
		if !g.Valid() {
			return fmt.Errorf("cra: PEC ground %q is not a known ground", g)
		}
	}
	if p.Grounds[len(p.Grounds)-1] == PECGroundOther && p.Reasoning == "" {
		return errors.New("cra: PEC ground 'other' requires reasoning")
	}
	if p.Reasoning == "" {
		return errors.New("cra: a PEC claim requires reasoning")
	}
	if len(p.Evidence) == 0 {
		return errors.New("cra: a PEC claim requires supporting evidence")
	}
	if p.DecisionAt == nil {
		return errors.New("cra: a PEC claim requires a recorded decision time")
	}
	if p.DecisionBy == "" {
		return errors.New("cra: a PEC claim requires a recorded decision maker")
	}
	return nil
}

// SetMitigationAvailable records the AEV mitigation event that anchors the final
// report, auditing the transition from "no anchor" to a concrete instant.
//
// A second call that changes the value is permitted — the mitigation date is
// corrected surprisingly often — but is recorded as a decision so the change is
// visible. A *later* mitigation date pushes the final-report deadline out,
// which is a fact an authority will examine, so it is never silent.
func (r Report) SetMitigationAvailable(at time.Time, actor, reason string, now time.Time) (Report, error) {
	if at.IsZero() {
		return r, errors.New("cra: mitigation_available_at is required")
	}
	if !r.EventType.Valid() {
		return r, fmt.Errorf("%w: cannot record a mitigation before the event type is determined (state %s)", ErrInvalidReport, r.State)
	}
	if r.EventType != EventTypeAEV {
		return r, fmt.Errorf("cra: mitigation_available_at is an AEV concept; %s final reports run from the 72-hour notification", r.EventType)
	}
	if r.MitigationAvailableAt != nil && r.MitigationAvailableAt.Equal(at) {
		return r, nil
	}
	prior := ""
	if r.MitigationAvailableAt != nil {
		prior = fmt.Sprintf(" (was %s)", r.MitigationAvailableAt.Format(time.RFC3339))
	}
	t := at
	r.MitigationAvailableAt = &t
	if now.IsZero() {
		now = time.Now()
	}
	r.UpdatedAt = now
	r.Decisions = append(r.Decisions, Decision{
		At:     now,
		From:   r.State,
		To:     r.State,
		Actor:  actor,
		Reason: fmt.Sprintf("mitigation available at %s%s: %s", at.Format(time.RFC3339), prior, reason),
	})
	return r, nil
}
