// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.

package cra

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ProductExposure is one (product, component) pair through which a
// vulnerability reaches a product with digital elements.
//
// This is the answer to "the CVE is exploited — now what?", expressed as a set
// of concrete exposures. The manufacturer's duty under Article 14 attaches to
// the *product*, not to the upstream component: nobody reports a library, they
// report the product that shipped it. Getting that distinction wrong in either
// direction is costly — collapsing everything to the component under-reports,
// and treating every SBOM hit as a separate product over-reports and fragments
// the evidence.
type ProductExposure struct {
	// ProductID identifies the product with digital elements. It is the same
	// identifier space as VEX product_id, so a VEX statement and an exposure
	// can be joined.
	ProductID string `json:"product_id"`

	// ProductName is the human name of the product.
	ProductName string `json:"product_name,omitempty"`

	// SbomID identifies the SBOM document that evidences the composition.
	SbomID uuid.UUID `json:"sbom_id"`

	// ComponentName and ComponentVersion are the third-party component as it
	// appears in the SBOM.
	ComponentName    string `json:"component_name"`
	ComponentVersion string `json:"component_version"`

	// ComponentPURL is the package URL, when the SBOM supplies one. It is a
	// stronger identity than a name and is preferred for joining.
	ComponentPURL string `json:"component_purl,omitempty"`

	// ComponentType is the SBOM component type (library, application, ...).
	// A vulnerable dev-time or test-only dependency is a materially different
	// exposure from a vulnerable runtime library, and the type is a hint
	// towards that, not a determination of it.
	ComponentType string `json:"component_type,omitempty"`

	// Reachability is what is known about whether the vulnerable code can
	// actually be reached. It is evidence for the human decision, never the
	// decision.
	Reachability Reachability `json:"reachability"`

	// MatchConfidence is the matcher's confidence in the component identity.
	// A fuzzy name match is weaker evidence of product applicability than a
	// PURL match, and that difference is retained rather than flattened.
	MatchConfidence string `json:"match_confidence,omitempty"`

	// LatestScanAt is when the composition was last observed. Exposure
	// evidence ages: an SBOM from last year is a different claim about the
	// current product than one from last week.
	LatestScanAt time.Time `json:"latest_scan_at,omitempty"`

	// VexStatements are the manufacturer's own applicability claims about this
	// CVE and product. They are claims, not determinations, and are carried
	// here so the decision-maker sees them.
	VexStatements []VexClaim `json:"vex_statements,omitempty"`
}

// Reachability states what is known about whether the vulnerable code is
// reachable in the product.
//
// The zero value is ReachabilityUnknown rather than ReachabilityReachable. A
// resolver that defaults to "reachable" invents a fact; one that defaults to
// "not reachable" silently under-reports. Unknown is the only honest default,
// and it is the value most products will actually be in.
type Reachability string

const (
	// ReachabilityUnknown — no reachability analysis has been performed.
	ReachabilityUnknown Reachability = "unknown"

	// ReachabilityReachable — the vulnerable code is reachable from an
	// untrusted input path. Evidence of applicability.
	ReachabilityReachable Reachability = "reachable"

	// ReachabilityNotReachable — the vulnerable code exists but is not on an
	// execution path an adversary can influence.
	ReachabilityNotReachable Reachability = "not_reachable"

	// ReachabilityInconclusive — analysis was attempted and did not resolve.
	// Distinct from NotReachable, which is a positive finding.
	ReachabilityInconclusive Reachability = "inconclusive"
)

// Known reports whether the reachability is an actual determination.
func (r Reachability) Known() bool {
	switch r {
	case ReachabilityReachable, ReachabilityNotReachable:
		return true
	}
	return false
}

// VexClaim is a manufacturer's VEX statement about a CVE and product.
type VexClaim struct {
	StatementID uuid.UUID `json:"statement_id"`
	// Status is the statement lifecycle state. Only "active" statements carry
	// weight; a draft or expired one is not a claim the manufacturer stands
	// behind.
	Status string `json:"status"`
	// Justification is the VEX justification code (e.g.
	// vulnerable_code_not_in_execute_path).
	Justification string `json:"justification"`
	// ImpactStatement is the accompanying narrative.
	ImpactStatement string `json:"impact_statement,omitempty"`
	// Confidence is the VEX confidence (unknown, reasonable, high).
	Confidence string `json:"confidence,omitempty"`
	// ValidUntil bounds the claim. An expired claim says nothing about the
	// present.
	ValidUntil *time.Time `json:"valid_until,omitempty"`
	// Expired reports whether ValidUntil has passed as of the assessment.
	Expired bool `json:"expired"`
}

// Active reports whether the claim currently stands.
func (v VexClaim) Active(now time.Time) bool {
	if !strings.EqualFold(v.Status, "active") {
		return false
	}
	if v.ValidUntil != nil && !v.ValidUntil.After(now) {
		return false
	}
	return true
}

// AssertsNotAffected reports whether the claim is, in substance, a positive
// assertion that the product is NOT affected.
//
// This is deliberately a pure predicate on the claim's content. Whether the
// claim is also *current* is a separate question, answered by Active(now);
// conflating the two would make it impossible to say "this manufacturer
// published a not_affected claim, but it expired last year" — which is a
// materially different situation from one that never stood at all.
//
// Note that it is not treated as an exclusion anywhere in this package. A
// not_affected VEX is the manufacturer's own claim about its own product,
// typically distributed publicly through CSAF. It is powerful evidence and
// belongs in the assessment — but silently dropping every report whose
// manufacturer published a not_affected statement would let a claim made in
// error erase a statutory duty with no trace. The claim is surfaced; the
// determination stays human.
func (v VexClaim) AssertsNotAffected() bool {
	switch v.Justification {
	case "component_not_present", "vulnerable_code_not_present",
		"vulnerable_code_not_in_execute_path",
		"vulnerable_code_cannot_be_controlled_by_adversary",
		"inline_mitigations_already_exist":
		return true
	}
	return false
}

// EvidenceSource is a source that has reported exploitation. Sources are
// evidence inputs, never regulatory decisions: ENISA EUVD, CISA KEV, a national
// CERT, a vendor advisory or the manufacturer's own telemetry each support a
// determination, and none of them makes one.
type EvidenceSource string

const (
	EvidenceSourceEUVD              EvidenceSource = "enisa_euvd"
	EvidenceSourceCISAKEV           EvidenceSource = "cisa_kev"
	EvidenceSourceNationalCERT      EvidenceSource = "national_cert"
	EvidenceSourceVendorAdvisory    EvidenceSource = "vendor_advisory"
	EvidenceSourceInternalTelemetry EvidenceSource = "internal_telemetry"
	EvidenceSourceExploitArtefact   EvidenceSource = "exploit_artefact"
)

// Valid reports whether s is a known evidence source.
func (s EvidenceSource) Valid() bool {
	switch s {
	case EvidenceSourceEUVD, EvidenceSourceCISAKEV, EvidenceSourceNationalCERT,
		EvidenceSourceVendorAdvisory, EvidenceSourceInternalTelemetry,
		EvidenceSourceExploitArtefact:
		return true
	}
	return false
}

// ExploitationSignal is one input asserting that a vulnerability is being
// exploited.
//
// Signal strength is retained rather than collapsed into a boolean. A national
// CERT's notification and a single unverified forum post are not the same
// evidence, and the difference is what a human needs in order to decide.
type ExploitationSignal struct {
	Source     EvidenceSource `json:"source"`
	Reference  string         `json:"reference"`
	ObservedAt time.Time      `json:"observed_at"`
	// Summary is what was observed.
	Summary string `json:"summary,omitempty"`
	// Corroborated reports whether a second independent source agrees.
	Corroborated bool `json:"corroborated,omitempty"`

	// ProductID scopes the signal to one product, when the source was
	// specific about where the exploitation was seen.
	//
	// This matters more than it looks. "CVE-2026-31337 is in the KEV list" is a
	// statement about the vulnerability and applies to every product it reaches.
	// "Actors are exploiting this against Gateway 3.x" is a statement about one
	// product, and must not be read as evidence about every other product that
	// happens to embed the same library. Collapsing the two is how a resolver
	// ends up either over-reporting across an entire estate or under-reporting
	// the one product actually under attack.
	//
	// Empty means the signal is vulnerability-scoped and applies to all
	// exposures.
	ProductID string `json:"product_id,omitempty"`
}

// AppliesTo reports whether the signal is evidence about a given product.
func (s ExploitationSignal) AppliesTo(productID string) bool {
	return s.ProductID == "" || s.ProductID == productID
}

// Strength buckets a signal for display without collapsing the underlying facts.
func (s ExploitationSignal) Strength() SignalStrength {
	switch {
	case s.Corroborated:
		return SignalStrengthCorroborated
	case s.Source == EvidenceSourceInternalTelemetry || s.Source == EvidenceSourceExploitArtefact:
		return SignalStrengthDirect
	case s.Source == EvidenceSourceNationalCERT || s.Source == EvidenceSourceVendorAdvisory:
		return SignalStrengthAuthoritative
	default:
		return SignalStrengthUncorroborated
	}
}

// SignalStrength is a coarse ordering of exploitation evidence.
type SignalStrength string

const (
	SignalStrengthUncorroborated SignalStrength = "uncorroborated"
	SignalStrengthAuthoritative  SignalStrength = "authoritative"
	SignalStrengthDirect         SignalStrength = "direct"
	SignalStrengthCorroborated   SignalStrength = "corroborated"
)

// ExposureInput is everything the resolver knows about one vulnerability.
type ExposureInput struct {
	OrgID  uuid.UUID
	VulnID uuid.UUID
	CVE    string
	EUVDID string

	// Exposures are the product/component pairs through which the
	// vulnerability is believed to reach a product.
	Exposures []ProductExposure

	// Signals are the exploitation evidence inputs.
	Signals []ExploitationSignal

	// CVSSBase is retained only so an operator can see it in the assessment.
	// It is never an input to the outcome: severity is a property of the
	// vulnerability, and Article 14 turns on exploitation.
	CVSSBase *float64

	// Awareness is the recorded awareness, if any. Its presence is a fact about
	// the clock, not about reportability.
	Awareness Awareness

	// ExistingReports are report IDs already opened for this vulnerability in
	// this org, so the resolver can flag an exposure that is already covered
	// instead of inviting a duplicate filing.
	ExistingReports []uuid.UUID
}

// Assessment is what the resolver concludes. It is a *scope* determination
// with attached evidence, not a reportability decision.
//
// The distinction is the whole point. The resolver answers "where does this
// vulnerability touch our products, and what do we know about each?". Whether
// an exposure is CRA-reportable is a regulatory determination that requires a
// human, a legal judgement and evidence the resolver does not have. Producing a
// boolean called `reportable` here would put a machine in the position of
// deciding a statutory duty, and the output would be indistinguishable from a
// legal conclusion.
type Assessment struct {
	OrgID     uuid.UUID
	VulnID    uuid.UUID
	CVE       string
	EUVDID    string
	CreatedAt time.Time

	// Exposures requiring assessment, ordered most- to least-urgent.
	Prioritised []PrioritisedExposure `json:"prioritised"`

	// AlreadyCovered lists exposures whose product already has an open report,
	// so the same event is not filed twice.
	AlreadyCovered []uuid.UUID `json:"already_covered,omitempty"`

	// BlockingGaps are the questions the resolver cannot answer. A
	// non-empty list is the expected state for most vulnerabilities, and it is
	// reported rather than hidden.
	BlockingGaps []Gap `json:"blocking_gaps,omitempty"`

	// NotExposed records that the vulnerability was assessed and touches no
	// product, with the reason. Distinguishing this from "not assessed" is what
	// stops a re-run from looking like new information.
	NotExposed *NotExposed `json:"not_exposed,omitempty"`
}

// PrioritisedExposure is one exposure with its ordering signals.
type PrioritisedExposure struct {
	ProductExposure

	// Signals are the exploitation evidence that applies to this exposure.
	Signals []ExploitationSignal `json:"signals,omitempty"`

	// StrongestSignal is the highest-strength signal observed.
	StrongestSignal SignalStrength `json:"strongest_signal"`

	// VexAssertsNotAffected is surfaced prominently so a not_affected claim is
	// visible without being acted upon automatically.
	VexAssertsNotAffected bool `json:"vex_asserts_not_affected"`

	// Gaps are the open questions for this exposure specifically.
	Gaps []Gap `json:"gaps,omitempty"`

	// AttentionRank orders exposures for review. Lower sorts first. It is a
	// work queue, not a risk score, and it deliberately does not incorporate
	// CVSS.
	AttentionRank int `json:"attention_rank"`

	// RankRationale explains the rank in words, so an operator can disagree
	// with it.
	RankRationale string `json:"rank_rationale"`
}

// NotExposed records a clean assessment.
type NotExposed struct {
	Reason string    `json:"reason"`
	Detail string    `json:"detail,omitempty"`
	At     time.Time `json:"at"`
}

// Gap is a question the resolver cannot answer from its inputs.
type Gap struct {
	Code   string `json:"code"`
	Detail string `json:"detail,omitempty"`
	// Blocking marks a gap that prevents a reportability determination.
	Blocking bool `json:"blocking"`
}

// Gap codes.
const (
	GapNoExploitationEvidence   = "no_exploitation_evidence"
	GapReachabilityUnknown      = "reachability_unknown"
	GapReachabilityInconclusive = "reachability_inconclusive"
	GapMatchConfidenceLow       = "match_confidence_low"
	GapStaleComposition         = "stale_composition"
	GapNoAwarenessRecorded      = "no_awareness_recorded"
	GapVexContradictsAssessment = "vex_asserts_not_affected"
)

// ErrNoExposureInput is returned when the input cannot be assessed at all.
var ErrNoExposureInput = fmt.Errorf("cra: exposure assessment requires a vulnerability identity")

// ResolveExposure walks the product graph and produces an Assessment.
//
// now is explicit so the result is a pure function of its inputs and can be
// tested against clock-dependent behaviour (VEX expiry, composition staleness)
// without touching the system clock.
func ResolveExposure(in ExposureInput, now time.Time) (Assessment, error) {
	if in.VulnID == uuid.Nil && in.CVE == "" {
		return Assessment{}, ErrNoExposureInput
	}
	if now.IsZero() {
		now = time.Now()
	}

	a := Assessment{
		OrgID:     in.OrgID,
		VulnID:    in.VulnID,
		CVE:       in.CVE,
		EUVDID:    in.EUVDID,
		CreatedAt: now,
	}

	if len(in.Exposures) == 0 {
		a.NotExposed = &NotExposed{
			Reason: "no_product_exposure",
			Detail: "the vulnerability does not appear in any SBOM for this organisation",
			At:     now,
		}
		return a, nil
	}

	for _, e := range in.Exposures {
		scoped := signalsFor(in.Signals, e.ProductID)
		pe := PrioritisedExposure{
			ProductExposure: e,
			Signals:         scoped,
			StrongestSignal: strongestSignal(scoped),
			Gaps:            gapsFor(e, in, now),
		}
		for _, v := range e.VexStatements {
			if v.AssertsNotAffected() && v.Active(now) {
				pe.VexAssertsNotAffected = true
				break
			}
		}
		if pe.VexAssertsNotAffected {
			pe.Gaps = append(pe.Gaps, Gap{
				Code:     GapVexContradictsAssessment,
				Detail:   "the manufacturer has published a not_affected VEX statement for this product",
				Blocking: false, // evidence, not a bar
			})
		}
		if in.Awareness.Validate() != nil {
			a.BlockingGaps = append(a.BlockingGaps, Gap{
				Code:     GapNoAwarenessRecorded,
				Detail:   "no evidenced awareness has been recorded, so no Article 14 clock can be started",
				Blocking: true,
			})
		}
		if len(scoped) == 0 {
			// Absence of exploitation evidence is the most common reason an
			// exposure is not reportable, and it is the reason a machine is
			// least entitled to conclude anything. Note this is evaluated per
			// product: a product nobody is attacking is not reportable, and
			// must not inherit the evidence gathered about a sibling product
			// that ships the same component.
			pe.Gaps = append(pe.Gaps, Gap{
				Code:     GapNoExploitationEvidence,
				Detail:   "no source has reported active exploitation against this product",
				Blocking: true,
			})
		}
		a.Prioritised = append(a.Prioritised, pe)
	}

	rankExposures(a.Prioritised)
	a.AlreadyCovered = in.ExistingReports
	sort.SliceStable(a.Prioritised, func(i, j int) bool {
		return a.Prioritised[i].AttentionRank < a.Prioritised[j].AttentionRank
	})
	return a, nil
}

// signalsFor narrows vulnerability-scoped and product-scoped evidence to what
// is actually evidence about one product.
func signalsFor(signals []ExploitationSignal, productID string) []ExploitationSignal {
	var out []ExploitationSignal
	for _, s := range signals {
		if s.AppliesTo(productID) {
			out = append(out, s)
		}
	}
	return out
}

// gapsFor computes the evidence gaps for one exposure.
func gapsFor(e ProductExposure, in ExposureInput, now time.Time) []Gap {
	var gaps []Gap
	if !e.Reachability.Known() {
		code := GapReachabilityUnknown
		detail := "no reachability analysis has been performed for this component"
		if e.Reachability == ReachabilityInconclusive {
			code = GapReachabilityInconclusive
			detail = "reachability analysis was attempted and did not resolve"
		}
		gaps = append(gaps, Gap{Code: code, Detail: detail, Blocking: true})
	}
	switch strings.ToLower(e.MatchConfidence) {
	case "low", "unknown", "":
		gaps = append(gaps, Gap{
			Code:     GapMatchConfidenceLow,
			Detail:   fmt.Sprintf("component identity was matched with %q confidence", e.MatchConfidence),
			Blocking: false,
		})
	}
	// Composition evidence older than a year is a materially weaker claim
	// about the current product. The threshold is a Transparenz choice, not a
	// regulatory one, and it is stated here so it is arguable.
	const staleComposition = 365 * 24 * time.Hour
	if !e.LatestScanAt.IsZero() && now.Sub(e.LatestScanAt) > staleComposition {
		gaps = append(gaps, Gap{
			Code:     GapStaleComposition,
			Detail:   "the SBOM evidencing this composition is over a year old",
			Blocking: false,
		})
	}
	return gaps
}

// rankExposures assigns attention order and a written rationale.
//
// The ordering deliberately excludes CVSS. Severity is a property of the
// vulnerability and says nothing about whether it is being exploited or which
// product needs attention first. A CVSS 9.8 that nobody is exploiting and a
// CVSS 5.3 being actively exploited against a shipped product are not ordered by
// their scores, and letting the score drive the queue is how the severity
// conflation re-enters through the back door.
func rankExposures(exposures []PrioritisedExposure) {
	for i := range exposures {
		var reasons []string
		rank := 0

		switch exposures[i].StrongestSignal {
		case SignalStrengthCorroborated:
			rank += 0
			reasons = append(reasons, "exploitation corroborated by more than one independent source")
		case SignalStrengthDirect:
			rank += 1
			reasons = append(reasons, "exploitation observed directly by us")
		case SignalStrengthAuthoritative:
			rank += 2
			reasons = append(reasons, "exploitation reported by an authoritative source")
		default:
			rank += 6
			reasons = append(reasons, "no corroborating exploitation evidence")
		}

		switch exposures[i].Reachability {
		case ReachabilityReachable:
			rank += 0
			reasons = append(reasons, "vulnerable code is reachable")
		case ReachabilityNotReachable:
			rank += 3
			reasons = append(reasons, "vulnerable code is not on an adversarial path")
		default:
			rank += 2
			reasons = append(reasons, "reachability is not established")
		}

		if exposures[i].VexAssertsNotAffected {
			rank += 2
			reasons = append(reasons, "a not_affected VEX statement is on record for this product")
		}
		if strings.ToLower(exposures[i].MatchConfidence) == "high" {
			rank -= 1
			reasons = append(reasons, "component identity matched with high confidence")
		}
		if rank < 0 {
			rank = 0
		}

		exposures[i].AttentionRank = rank
		exposures[i].RankRationale = strings.Join(reasons, "; ")
	}
}

// strongestSignal returns the strongest signal observed, and whether any signal
// was observed at all.
//
// The distinction matters: "one feed asserts exploitation" and "nobody has
// asserted anything" are very different positions in an assessment, and
// collapsing them into a single empty value would let the first look like the
// second. An uncorroborated signal is therefore reported as uncorroborated,
// never as absent.
func strongestSignal(signals []ExploitationSignal) SignalStrength {
	var best SignalStrength
	seen := false
	for _, s := range signals {
		if s.Source == "" || s.Reference == "" {
			continue
		}
		seen = true
		if strengthRank(s.Strength()) > strengthRank(best) {
			best = s.Strength()
		}
	}
	if !seen {
		return ""
	}
	if best == "" {
		return SignalStrengthUncorroborated
	}
	return best
}

func strengthRank(s SignalStrength) int {
	switch s {
	case SignalStrengthCorroborated:
		return 3
	case SignalStrengthDirect:
		return 2
	case SignalStrengthAuthoritative:
		return 1
	default:
		return 0
	}
}
