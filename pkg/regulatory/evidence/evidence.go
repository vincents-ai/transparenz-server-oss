// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.

// Package evidence is the shared technical evidence layer beneath the CRA and
// NIS2 regulatory engines.
//
// # What this is for
//
// One artefact can satisfy evidence requirements under more than one regime. A
// vulnerability that is being exploited against a shipped product is
// simultaneously CRA Article 14 evidence and, if the entity is in scope, a
// NIS2 Article 23 significant incident. Today that artefact is recorded twice,
// in two engines, with no link — so an authority asking about one regime cannot
// be shown the other's evidence, and nothing can answer "does this also
// implicate an incident?"
//
// This layer records the fact and its provenance once. Each regime then maps
// that shared evidence onto its own obligation.
//
// # What this deliberately does not contain
//
// No deadline. No workflow state. No reportability determination. No reference
// to either regulation anywhere in the types below.
//
// That is not minimalism for its own sake. The two regimes disagree correctly
// and must stay able to: CRA has an AEV class anchored on the arrival of a
// mitigating measure at 14 days, and a severe-incident class anchored on the
// 72-hour notification at one calendar month; NIS2 has a single timeline
// anchored on awareness. Put those deadlines here and the layer would have to
// know which regime it was being used for, at which point it stops being shared
// evidence and becomes a third engine nobody owns.
//
// A regulatory obligation attaches to a product or an entity, and the two
// regimes scope those differently. The layer records what the evidence is
// about; the mapping above records whose duty it engages.
package evidence

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Origin classifies how something was learned. It is a provenance class, not a
// regulatory conclusion: every one of these is evidence supporting a judgement
// that a person makes elsewhere.
type Origin string

const (
	OriginInternalTelemetry   Origin = "internal_telemetry"
	OriginCERT                Origin = "cert"
	OriginVendorAdvisory      Origin = "vendor_advisory"
	OriginThreatIntelligence  Origin = "intelligence"
	OriginExploitArtefact     Origin = "exploit_evidence"
	OriginCustomerReport      Origin = "customer_report"
	OriginPartnerNotification Origin = "partner_notification"
	OriginUnknown             Origin = "unknown"
)

// Valid reports whether o is a known origin.
func (o Origin) Valid() bool {
	switch o {
	case OriginInternalTelemetry, OriginCERT, OriginVendorAdvisory,
		OriginThreatIntelligence, OriginExploitArtefact, OriginCustomerReport,
		OriginPartnerNotification, OriginUnknown:
		return true
	}
	return false
}

// Certainty is the strength of an observation, and it exists so that weak
// evidence stays visibly weak.
type Certainty string

const (
	// CertaintyReported means someone asserted it. It is the weakest class and
	// is never sufficient on its own for a determination.
	CertaintyReported Certainty = "reported"

	// CertaintyCorroborated means more than one independent source agrees.
	CertaintyCorroborated Certainty = "corroborated"

	// CertaintyObserved means observed directly by the organisation.
	CertaintyObserved Certainty = "observed"
)

// Valid reports whether c is a known certainty.
func (c Certainty) Valid() bool {
	switch c {
	case CertaintyReported, CertaintyCorroborated, CertaintyObserved:
		return true
	}
	return false
}

// SubjectKind is what an observation is about. It is deliberately about the
// subject, not the duty: a product and an entity are different subjects with
// different legal scopes, and conflating them is how entity duties get applied
// to products.
type SubjectKind string

const (
	// SubjectProductWithDigitalElements is a product placed on the EU market.
	// CRA Article 14 attaches here.
	SubjectProductWithDigitalElements SubjectKind = "product"

	// SubjectEssentialOrImportantEntity is an entity in NIS2 scope. NIS2
	// Article 23 attaches here.
	SubjectEssentialOrImportantEntity SubjectKind = "entity"
)

// Valid reports whether s is a known subject kind.
func (s SubjectKind) Valid() bool {
	return s == SubjectProductWithDigitalElements || s == SubjectEssentialOrImportantEntity
}

// Observation is one piece of shared technical evidence, recorded once and
// mapped onto whichever obligations it engages.
//
// It is a fact and its provenance. It carries no deadline and no
// determination, because an observation that has been used to conclude
// something and an observation that has not are very different things, and
// conflating them means a raw indicator can be mistaken for a finding.
type Observation struct {
	ID    uuid.UUID `json:"id"`
	OrgID uuid.UUID `json:"org_id"`

	// Kind classifies the observation without reference to a regulation.
	Kind Kind `json:"kind"`

	// Title is a one-line human summary.
	Title string `json:"title"`
	// Summary is the detail.
	Summary string `json:"summary,omitempty"`

	// Origin is how the organisation came to know.
	Origin Origin `json:"origin"`

	// Certainty is the strength of the observation. Weak evidence is recorded
	// as weak rather than rounded up, because an authority reading this later
	// needs to know it was one person's assertion.
	Certainty Certainty `json:"certainty"`

	// ObservedAt is when the fact occurred or was observed. It is NOT the
	// awareness instant for either regime: an obligation's clock starts when
	// the manufacturer became aware, which is a regulatory mapping, not a
	// property of the evidence.
	ObservedAt time.Time `json:"observed_at"`

	// RecordedAt is when this system persisted it, and RecordedBy who. The gap
	// between observation and recording is itself evidence.
	RecordedAt time.Time `json:"recorded_at"`
	RecordedBy string    `json:"recorded_by,omitempty"`

	// Artefact is a durable reference to what substantiates the observation —
	// a capture, a stored advisory, a log export, a ticket. Mandatory: a bare
	// assertion is not evidence and would not survive a post-market audit.
	Artefact string `json:"artefact"`

	// Subjects is what this observation is about. An observation with no
	// subject cannot be mapped to any obligation, so it is meaningless.
	Subjects []Subject `json:"subjects"`

	// Related is a free reference to something already recorded (an SBOM, a
	// vulnerability, a scan). It links without asserting a relationship the
	// evidence does not support.
	Related []Reference `json:"related,omitempty"`
}

// Kind classifies an observation.
type Kind string

const (
	// KindActiveExploitation is exploitation observed in the wild.
	KindActiveExploitation Kind = "active_exploitation"

	// KindSevereIncident is an incident affecting the security of a product
	// or the operation of an entity.
	KindSevereIncident Kind = "severe_incident"

	// KindVulnerability is a vulnerability, with no exploitation claim
	// attached. A CVE on its own is not evidence of anything regulatory, and
	// recording it as such would inflate every count.
	KindVulnerability Kind = "vulnerability"

	// KindCompromise is an actual compromise of a subject.
	KindCompromise Kind = "compromise"

	// KindControlFailure is a failure of an organisational or technical
	// control.
	KindControlFailure Kind = "control_failure"
)

// Valid reports whether k is a known kind.
func (k Kind) Valid() bool {
	switch k {
	case KindActiveExploitation, KindSevereIncident, KindVulnerability,
		KindCompromise, KindControlFailure:
		return true
	}
	return false
}

// Subject is what an observation concerns, kept deliberately regime-neutral.
type Subject struct {
	Kind SubjectKind `json:"kind"`

	// Identifier is the product or entity id in whichever system the
	// organisation uses. It is opaque here: this layer does not resolve it,
	// because resolving it would mean knowing a specific product model.
	Identifier string `json:"identifier"`

	// Name is a human label.
	Name string `json:"name,omitempty"`

	// SbomID links a product subject to the SBOM evidencing its composition,
	// when that is known. It is the most valuable single field here: it is
	// what lets a claim be checked rather than taken on trust.
	SbomID *uuid.UUID `json:"sbom_id,omitempty"`
}

// Reference points at something recorded elsewhere.
type Reference struct {
	Kind string    `json:"kind"`
	ID   uuid.UUID `json:"id"`
}

// ErrIncomplete is returned when an observation cannot be relied on.
var ErrIncomplete = errors.New("evidence: observation is not complete enough to be relied on")

// Validate checks that an observation is fit to be relied on.
//
// The requirements are strict on purpose. Evidence that fails this is worse
// than no evidence, because it will be mapped onto obligations and will carry
// a determination made on its basis.
func (o Observation) Validate() error {
	if o.OrgID == uuid.Nil {
		return fmt.Errorf("%w: no organisation", ErrIncomplete)
	}
	if !o.Kind.Valid() {
		return fmt.Errorf("%w: unknown kind %q", ErrIncomplete, o.Kind)
	}
	if !o.Origin.Valid() {
		return fmt.Errorf("%w: unknown origin %q", ErrIncomplete, o.Origin)
	}
	if !o.Certainty.Valid() {
		return fmt.Errorf("%w: unknown certainty %q", ErrIncomplete, o.Certainty)
	}
	if o.ObservedAt.IsZero() {
		return fmt.Errorf("%w: no observation time", ErrIncomplete)
	}
	if strings.TrimSpace(o.Title) == "" {
		return fmt.Errorf("%w: no title", ErrIncomplete)
	}
	if strings.TrimSpace(o.Artefact) == "" {
		return fmt.Errorf(
			"%w: no artefact reference; a bare assertion is not evidence and will not "+
				"survive a post-market audit", ErrIncomplete)
	}
	if len(o.Subjects) == 0 {
		return fmt.Errorf(
			"%w: no subject; without one the observation cannot be mapped to any "+
				"obligation, so it is not evidence of anything", ErrIncomplete)
	}
	for _, s := range o.Subjects {
		if !s.Kind.Valid() {
			return fmt.Errorf("%w: unknown subject kind %q", ErrIncomplete, s.Kind)
		}
		if strings.TrimSpace(s.Identifier) == "" {
			return fmt.Errorf("%w: subject has no identifier", ErrIncomplete)
		}
	}
	return nil
}

// AppliesTo reports whether the observation concerns a given subject kind.
func (o Observation) AppliesTo(kind SubjectKind) bool {
	for _, s := range o.Subjects {
		if s.Kind == kind {
			return true
		}
	}
	return false
}

// Amendment is a retained correction to an observation.
//
// Observations are corrected in practice: a bad timestamp, a misattributed
// artefact, a subject that turned out to be the wrong one. How the correction
// was handled is exactly what an authority examines, so the before-and-after
// is retained rather than overwritten.
type Amendment struct {
	ID            uuid.UUID `json:"id"`
	ObservationID uuid.UUID `json:"observation_id"`

	// Field names what changed, e.g. "observed_at" or "subjects".
	Field string `json:"field"`

	// OldValue and NewValue are the before and after, as strings. They are
	// strings because the fields differ in type and a lossy rendering is
	// preferable to a claim of structure the values do not share.
	OldValue string `json:"old_value"`
	NewValue string `json:"new_value"`

	Reason    string    `json:"reason"`
	Actor     string    `json:"actor"`
	AmendedAt time.Time `json:"amended_at"`
}

// Validate checks an amendment is auditable.
func (a Amendment) Validate() error {
	if a.ObservationID == uuid.Nil {
		return fmt.Errorf("%w: amendment has no observation", ErrIncomplete)
	}
	if strings.TrimSpace(a.Field) == "" {
		return fmt.Errorf("%w: amendment names no field", ErrIncomplete)
	}
	if a.OldValue == a.NewValue {
		return fmt.Errorf("%w: amendment changes nothing", ErrIncomplete)
	}
	if strings.TrimSpace(a.Reason) == "" {
		return fmt.Errorf("%w: an uncorroborated amendment is not auditable", ErrIncomplete)
	}
	if strings.TrimSpace(a.Actor) == "" {
		return fmt.Errorf("%w: amendment has no actor", ErrIncomplete)
	}
	if a.AmendedAt.IsZero() {
		return fmt.Errorf("%w: amendment has no time", ErrIncomplete)
	}
	return nil
}

// ObligationLink is a regime's mapping of one observation onto one of its own
// obligations.
//
// This is where the regimes stay separate. The evidence is shared; the duty it
// engages is not, and two regulators can impose different duties from the same
// fact — a single exploitation event can be an Article 14 reportable event and
// an Article 23 significant incident simultaneously, with different clocks,
// different recipients and different scopes. A single boolean on the
// observation would destroy exactly that.
type ObligationLink struct {
	ObservationID uuid.UUID `json:"observation_id"`

	// Regime identifies the regulatory engine making the mapping.
	Regime Regime `json:"regime"`

	// Obligation is the provision engaged, e.g. "CRA Article 14" or
	// "NIS2 Article 23".
	Obligation string `json:"obligation"`

	// AwarenessAt is the regime's clock anchor, mapped from the observation.
	//
	// It is here and not on the Observation because the two regimes anchor
	// differently, and because an authority asking "why does your Article 14
	// clock start then?" needs the answer stated in Article 14 terms.
	AwarenessAt *time.Time `json:"awareness_at,omitempty"`

	// Authority is the recipient: a national CSIRT, a market surveillance
	// authority, or ENISA. Different per regime, and frequently different for
	// the same fact.
	Authority string `json:"authority,omitempty"`

	// Rationale is why this observation engages this obligation for this
	// subject. It is a mapping statement, and an authority will ask for it.
	Rationale string `json:"rationale"`
}

// Regime identifies a regulatory engine.
type Regime string

const (
	// RegimeCRA is the Cyber Resilience Act.
	RegimeCRA Regime = "CRA"

	// RegimeNIS2 is the NIS2 Directive.
	RegimeNIS2 Regime = "NIS2"
)

// Valid reports whether r is a known regime.
func (r Regime) Valid() bool { return r == RegimeCRA || r == RegimeNIS2 }

// Validate checks a mapping statement is defensible.
func (l ObligationLink) Validate() error {
	if l.ObservationID == uuid.Nil {
		return fmt.Errorf("%w: link has no observation", ErrIncomplete)
	}
	if !l.Regime.Valid() {
		return fmt.Errorf("%w: unknown regime %q", ErrIncomplete, l.Regime)
	}
	if strings.TrimSpace(l.Obligation) == "" {
		return fmt.Errorf("%w: link names no obligation", ErrIncomplete)
	}
	if strings.TrimSpace(l.Rationale) == "" {
		return fmt.Errorf(
			"%w: a mapping without a rationale cannot be explained to the authority "+
				"it is being made to", ErrIncomplete)
	}
	return nil
}

// Bundle is an observation together with every obligation it engages.
//
// It is the answer to "show me this evidence and everything it triggered",
// which is the question a single regulator asks and the question two of them
// ask between them. Rendering it as one document with the mappings listed
// separately is what keeps the regimes distinct while showing the shared fact
// once.
type Bundle struct {
	Observation Observation      `json:"observation"`
	Amendments  []Amendment      `json:"amendments,omitempty"`
	Links       []ObligationLink `json:"links"`
}

// EngagedRegimes returns the distinct regimes this evidence has engaged.
func (b Bundle) EngagedRegimes() []Regime {
	seen := map[Regime]bool{}
	var out []Regime
	for _, l := range b.Links {
		if !seen[l.Regime] {
			seen[l.Regime] = true
			out = append(out, l.Regime)
		}
	}
	return out
}

// CrossRegime reports whether this evidence engages more than one regime, which
// is the case the shared layer exists to represent.
func (b Bundle) CrossRegime() bool { return len(b.EngagedRegimes()) > 1 }
