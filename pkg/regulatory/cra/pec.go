// SPDX-FileCopyrightText: 2026 Vincent Palmer
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Transparenz, an open-source CRA compliance server.
// It is licensed under the GNU Affero General Public License v3.0; see LICENSE.

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
	// The three grounds the Regulation actually provides.
	//
	// Article 16(2) permits withholding the full 72-hour notification from
	// simultaneous access by ENISA, and delaying wider dissemination, only where
	// the manufacturer indicates one of these. They are narrow and factual.

	// PECGroundExploitedInOneMemberState — the vulnerability has been actively
	// exploited by a malicious actor and, on the information available, in no
	// Member State other than that of the coordinating CSIRT.
	PECGroundExploitedInOneMemberState PECGrounds = "exploited_in_one_member_state"

	// PECGroundEssentialInterests — immediate further dissemination would likely
	// supply information whose disclosure would be contrary to that Member
	// State's essential interests.
	PECGroundEssentialInterests PECGrounds = "essential_interests"

	// PECGroundImminentHighRisk — the vulnerability poses an imminent high
	// cybersecurity risk stemming from further dissemination.
	PECGroundImminentHighRisk PECGrounds = "imminent_high_risk"

	// The grounds below are a local vocabulary that predates the alignment with
	// Article 16(2), and none of them is a statutory ground. They remain KNOWN so
	// that claims recorded under them are still readable: silently failing to
	// parse a filed claim would be worse than reading it and flagging it. They are
	// NOT accepted for new claims — see Validate.
	//
	// Deprecated: use one of the three statutory grounds above.
	PECGroundActiveRemediation   PECGrounds = "active_remediation"
	PECGroundOperationalSecurity PECGrounds = "operational_security"
	PECGroundLawEnforcement      PECGrounds = "law_enforcement"
	PECGroundPersonalData        PECGrounds = "personal_data"
	PECGroundOther               PECGrounds = "other"
)

// StatutoryPECGrounds returns the three Article 16(2) grounds, for error messages
// that have to tell a filer what they may choose instead.
func StatutoryPECGrounds() []PECGrounds {
	return []PECGrounds{
		PECGroundExploitedInOneMemberState,
		PECGroundEssentialInterests,
		PECGroundImminentHighRisk,
	}
}

// Valid reports whether g is a known ground.
// Valid reports whether g is a ground this package knows about, statutory or
// superseded.
//
// It is deliberately wider than Statutory: a claim recorded under the older
// vocabulary must still read back correctly, because a filer's historical claim is
// a fact about what they asserted, not a parse error. What separates the two is
// whether a NEW claim may use the ground.
func (g PECGrounds) Valid() bool {
	switch g {
	case PECGroundExploitedInOneMemberState, PECGroundEssentialInterests, PECGroundImminentHighRisk:
		return true
	case PECGroundActiveRemediation, PECGroundOperationalSecurity,
		PECGroundLawEnforcement, PECGroundPersonalData, PECGroundOther:
		return true
	}
	return false
}

// Statutory reports whether g is one of the three grounds Article 16(2) provides.
func (g PECGrounds) Statutory() bool {
	switch g {
	case PECGroundExploitedInOneMemberState, PECGroundEssentialInterests, PECGroundImminentHighRisk:
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
		if g.Statutory() {
			continue
		}
		if g.Valid() {
			// Known, but not a ground the SRP form offers. Refusing it here rather
			// than accepting a plausible-sounding substitute is the whole point:
			// the authority has three grounds, and a claim under one of these would
			// assert a legal basis that does not exist.
			return fmt.Errorf("%w: PEC ground %q is not one of the Article 16(2) grounds; "+
				"use one of %v. It remains readable on claims recorded before this "+
				"alignment, but a new claim cannot assert it", ErrInvalidReport, g, StatutoryPECGrounds())
		}
		return fmt.Errorf("cra: PEC ground %q is not a known ground", g)
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
