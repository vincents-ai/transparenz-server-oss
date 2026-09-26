// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.

// Package cra implements the regulatory domain model for CRA Article 14
// reporting of actively exploited vulnerabilities (AEV) and severe incidents
// (SI), aligned to the ENISA Single Reporting Platform (SRP) workflow as
// described in the CRA SRP Glossary v1.3 (ENISA, 2026-09-10).
//
// The package is deliberately pure: models, transitions and deadline rules
// with no database, HTTP or clock dependencies beyond an explicit `now`.
// Anything that must be provable to a regulator is a value in this package,
// not a side effect somewhere else in the service.
//
// # Why this package exists
//
// The pre-2026 implementation conflated three different things:
//
//   - "is this vulnerability critical?" (a CVSS judgement), and
//   - "is this vulnerability being exploited?" (a factual condition), and
//   - "when did the manufacturer know?" (an evidentiary event).
//
// CRA Article 14 keys the clock to the third, and gates the duty on the
// second. The first is a triage heuristic with no regulatory standing.
// Separating them is the substance of this package; see State, EventType and
// Awareness respectively.
package cra

import (
	"errors"
	"fmt"
	"time"
)

// Reporting windows. These are the Article 14 statutory periods, expressed as
// durations where a duration is the correct model and left to DeadlineAt for
// the one case (the AEV final report) that is anchored to a different event.
const (
	// EarlyWarningWindow is Art.14(2): within 24 hours of awareness.
	EarlyWarningWindow = 24 * time.Hour

	// NotificationWindow is Art.14(3): within 72 hours of awareness.
	NotificationWindow = 72 * time.Hour

	// AEVFinalReportWindow is Art.14(4) for actively exploited vulnerabilities:
	// within 14 days of a corrective or mitigating measure becoming available.
	// This window is *not* anchored to awareness — see DeadlineAt.
	AEVFinalReportWindow = 14 * 24 * time.Hour

	// SIFinalReportMonths is Art.14(4) for severe incidents: within one month
	// of the 72-hour notification. Modelled as a calendar month, not 30 days:
	// February and 31-day months differ, and the difference decides compliance.
	SIFinalReportMonths = 1
)

// ErrNoAwareness is returned when a deadline is requested for an event that has
// no recorded awareness. Callers must treat this as "not yet reportable" rather
// than falling back to another timestamp — falling back is precisely the defect
// this package replaces.
var ErrNoAwareness = errors.New("cra: no awareness recorded; the reporting clock has no anchor")

// AwarenessSource classifies *how* the manufacturer learned of the event.
// It is not the same as the detection channel that found a CVE: a scanner may
// discover the vulnerability long before any evidence of exploitation exists,
// and only the latter starts the Article 14 clock.
type AwarenessSource string

const (
	// AwarenessSourceInternalTelemetry is the manufacturer's own detection —
	// the organisation's own security monitoring, bug bounty triage, or its
	// own incident response. Strongest provenance: the manufacturer observed
	// exploitation directly.
	AwarenessSourceInternalTelemetry AwarenessSource = "internal_telemetry"

	// AwarenessSourceCERT is a national CERT or CSIRT notification (e.g. BSI
	// CERT-Bund). The authority itself told us.
	AwarenessSourceCERT AwarenessSource = "cert"

	// AwarenessSourceVendorAdvisory is a supplier or upstream maintainer
	// advisory disclosing active exploitation.
	AwarenessSourceVendorAdvisory AwarenessSource = "vendor_advisory"

	// AwarenessSourceIntelligence is third-party threat intelligence
	// (ENISA EUVD, CISA KEV, commercial feeds). This is evidence, not a
	// regulatory determination — see Classification.
	AwarenessSourceIntelligence AwarenessSource = "intelligence"

	// AwarenessSourceExploitEvidence is a public proof-of-concept, a
	// packet-capture artefact, or similar direct exploitation artefact.
	AwarenessSourceExploitEvidence AwarenessSource = "exploit_evidence"
)

// Valid reports whether s is a known awareness source.
func (s AwarenessSource) Valid() bool {
	switch s {
	case AwarenessSourceInternalTelemetry, AwarenessSourceCERT,
		AwarenessSourceVendorAdvisory, AwarenessSourceIntelligence,
		AwarenessSourceExploitEvidence:
		return true
	}
	return false
}

// Awareness is the Article 14 clock anchor: the moment the manufacturer became
// aware, together with the provenance that makes that moment defensible.
//
// The brief this models is blunt — the clock runs from awareness, not from CVE
// publication, not from ingestion, not from a scan, not from a ticket, and not
// from submission. Those are all *later* or *earlier-but-irrelevant* events,
// and anchoring on them silently moves the deadline in whichever direction is
// more convenient for the filer. Every one of them is a defect, not a variant.
type Awareness struct {
	// AwarenessAt is the instant the manufacturer became aware. All Article 14
	// deadlines derive from this value. Required.
	AwarenessAt time.Time

	// Source is the provenance class. Required.
	Source AwarenessSource

	// Evidence is a durable reference to the artefact that establishes the
	// awareness instant — a stored advisory snapshot, an export of the feed
	// entry, a ticket or incident record, a capture. Required.
	//
	// A bare timestamp is not defensible in a post-market audit: the question
	// asked months later is "how do you know you knew, and when did you find
	// out?" Evidence is the answer.
	Evidence string

	// Reasoning is the human justification for the recorded instant when it is
	// not self-evident from the evidence — e.g. why a 03:00 advisory was
	// treated as awareness at 09:00 the next working day. Optional but
	// strongly recommended whenever AwarenessAt is not exactly the source's
	// own timestamp.
	Reasoning string

	// RecordedAt is when this system persisted the awareness fact. Distinct
	// from AwarenessAt: awareness precedes recording, and the gap is itself
	// evidence (a long gap is discoverable and must be explainable).
	// GORM-populated, not caller-supplied.
	RecordedAt time.Time

	// RecordedBy identifies the actor (a principal ID) that recorded the
	// awareness. GORM-populated from the authenticated caller.
	RecordedBy string
}

// Validate reports whether the awareness is fit to anchor a regulatory clock.
func (a Awareness) Validate() error {
	if a.AwarenessAt.IsZero() {
		return fmt.Errorf("%w: AwarenessAt is zero", ErrNoAwareness)
	}
	if !a.Source.Valid() {
		return fmt.Errorf("cra: awareness source %q is not a known source", a.Source)
	}
	if a.Evidence == "" {
		return errors.New("cra: awareness requires an evidence reference")
	}
	return nil
}

// IsReportableAnchor reports whether this awareness can legitimately start an
// Article 14 clock. Only awareness backed by evidence qualifies; intelligence
// that merely notes a CVE is not awareness of *exploitation*.
func (a Awareness) IsReportableAnchor() bool { return a.Validate() == nil }

// AwarenessAuditEntry records a change to an awareness instant.
//
// This exists because awareness is not truly immutable in practice — late
// discovery, timezone misunderstandings and bad feed data all produce
// corrections — and because how you handled a correction is exactly what an
// authority will examine. Overwriting AwarenessAt destroys the history needed
// to answer "was the 24-hour requirement met?".
type AwarenessAuditEntry struct {
	// OldValue is the previously recorded instant. Zero when this entry
	// records the initial determination.
	OldValue time.Time

	// NewValue is the corrected instant.
	NewValue time.Time

	// Actor is the principal that made the change.
	Actor string

	// At is when the change was made.
	At time.Time

	// Reason is the mandatory justification. A correction without a reason is
	// not auditable and is rejected by Validate.
	Reason string

	// EvidenceReference points at the evidence supporting the new value.
	EvidenceReference string
}

// Validate reports whether the audit entry is complete enough to be relied on.
func (e AwarenessAuditEntry) Validate() error {
	if e.NewValue.IsZero() {
		return errors.New("cra: awareness audit entry requires a new value")
	}
	if e.Actor == "" {
		return errors.New("cra: awareness audit entry requires an actor")
	}
	if e.At.IsZero() {
		return errors.New("cra: awareness audit entry requires a timestamp")
	}
	if e.Reason == "" {
		return errors.New("cra: awareness correction requires a stated reason")
	}
	if e.EvidenceReference == "" {
		return errors.New("cra: awareness correction requires an evidence reference")
	}
	return nil
}

// IsCorrection reports whether this entry changes an existing value rather than
// recording the initial determination. Corrections additionally require a
// reason, an actor and evidence.
func (e AwarenessAuditEntry) IsCorrection() bool { return !e.OldValue.IsZero() }

// AwarenessCorrection describes a pending amendment to a recorded awareness
// instant. Applying a correction is a distinct, audited operation — see
// ApplyAwarenessCorrection.
type AwarenessCorrection struct {
	NewValue time.Time
	Reason   string
	Evidence string
	Actor    string
	At       time.Time
	Clock    func() time.Time
}

// ApplyAwarenessCorrection validates a correction and returns the resulting
// awareness plus the audit entry to persist. It is a pure function: it does not
// write anything, so the caller cannot accidentally update the row and skip the
// audit entry.
//
// Important: a correction does not retroactively rewrite whether a deadline was
// met. The submitted milestones carry their own recorded timestamps, so the
// variance between the original and corrected anchor remains visible. Silently
// moving a deadline that has already been breached would destroy the only
// evidence of the breach.
func ApplyAwarenessCorrection(current Awareness, c AwarenessCorrection) (Awareness, AwarenessAuditEntry, error) {
	if c.Clock == nil {
		c.Clock = time.Now
	}
	if c.At.IsZero() {
		c.At = c.Clock()
	}
	if c.NewValue.IsZero() {
		return current, AwarenessAuditEntry{}, errors.New("cra: correction requires a new awareness value")
	}
	if c.NewValue.Equal(current.AwarenessAt) {
		return current, AwarenessAuditEntry{}, errors.New("cra: correction does not change the awareness instant")
	}
	entry := AwarenessAuditEntry{
		OldValue:          current.AwarenessAt,
		NewValue:          c.NewValue,
		Actor:             c.Actor,
		At:                c.At,
		Reason:            c.Reason,
		EvidenceReference: c.Evidence,
	}
	if err := entry.Validate(); err != nil {
		return current, AwarenessAuditEntry{}, err
	}
	updated := current
	updated.AwarenessAt = c.NewValue
	if c.Evidence != "" {
		updated.Evidence = c.Evidence
	}
	if c.Reason != "" {
		updated.Reasoning = c.Reason
	}
	return updated, entry, nil
}
