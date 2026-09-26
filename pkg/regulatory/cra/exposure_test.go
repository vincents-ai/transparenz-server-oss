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

var assessedAt = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

func exposure(product string, version string) ProductExposure {
	return ProductExposure{
		ProductID:        product,
		ProductName:      product,
		SbomID:           uuid.New(),
		ComponentName:    "libfoo",
		ComponentVersion: version,
		ComponentPURL:    "pkg:generic/libfoo@" + version,
		ComponentType:    "library",
		Reachability:     ReachabilityReachable,
		MatchConfidence:  "high",
		LatestScanAt:     assessedAt.Add(-30 * 24 * time.Hour),
	}
}

func signal(source EvidenceSource, corroborated bool) ExploitationSignal {
	return ExploitationSignal{
		Source:       source,
		Reference:    "ref-" + string(source),
		ObservedAt:   assessedAt.Add(-6 * time.Hour),
		Summary:      "observed exploitation in the wild",
		Corroborated: corroborated,
	}
}

// scopedSignal is evidence that names the product it was observed against.
func scopedSignal(source EvidenceSource, productID string, corroborated bool) ExploitationSignal {
	s := signal(source, corroborated)
	s.ProductID = productID
	s.Reference = "ref-" + string(source) + "-" + productID
	return s
}

// --- the resolver resolves scope, and does not decide reportability ---------

func TestResolverProducesScopeNotAReportabilityVerdict(t *testing.T) {
	in := ExposureInput{
		OrgID:     uuid.New(),
		VulnID:    uuid.New(),
		CVE:       "CVE-2026-31337",
		Exposures: []ProductExposure{exposure("gateway", "2.2.0")},
		Signals:   []ExploitationSignal{signal(EvidenceSourceInternalTelemetry, true)},
		Awareness: awareAt(t, "2026-09-26T06:00:00Z"),
	}
	a, err := ResolveExposure(in, assessedAt)
	require.NoError(t, err)
	require.Len(t, a.Prioritised, 1)

	// The output deliberately has no boolean called "reportable". The type has
	// no such field, and a caller cannot infer one without making the
	// determination itself with the evidence attached to each exposure.
	assert.Nil(t, a.NotExposed)
	assert.Equal(t, 0, a.Prioritised[0].AttentionRank)
	assert.Contains(t, a.Prioritised[0].RankRationale, "exploitation")
}

func TestAbsentAwarenessIsABlockingGapNotAnExclusion(t *testing.T) {
	in := ExposureInput{
		VulnID:    uuid.New(),
		CVE:       "CVE-2026-31337",
		Exposures: []ProductExposure{exposure("gateway", "2.2.0")},
		Signals:   []ExploitationSignal{signal(EvidenceSourceInternalTelemetry, true)},
		// No awareness: the clock cannot start.
	}
	a, err := ResolveExposure(in, assessedAt)
	require.NoError(t, err)
	require.NotEmpty(t, a.BlockingGaps)
	assert.Equal(t, GapNoAwarenessRecorded, a.BlockingGaps[0].Code)
	assert.True(t, a.BlockingGaps[0].Blocking)
}

func TestNoExposureIsRecordedAsACleanAssessmentNotSilence(t *testing.T) {
	in := ExposureInput{VulnID: uuid.New(), CVE: "CVE-2026-31337"}
	a, err := ResolveExposure(in, assessedAt)
	require.NoError(t, err)
	require.NotNil(t, a.NotExposed)
	assert.Equal(t, "no_product_exposure", a.NotExposed.Reason)
	assert.Empty(t, a.Prioritised)
}

func TestEmptyInputIsRejected(t *testing.T) {
	_, err := ResolveExposure(ExposureInput{OrgID: uuid.New()}, assessedAt)
	require.ErrorIs(t, err, ErrNoExposureInput)
}

// --- reportability turns on exploitation, never on severity ---------------

func TestCriticalSeverityWithoutExploitationEvidenceIsFlaggedNotPromoted(t *testing.T) {
	// CVSS 9.8, present in a shipped product, zero exploitation evidence. The
	// severity is carried into the assessment for an operator to read and is
	// not an input to the outcome.
	score := 9.8
	in := ExposureInput{
		VulnID:    uuid.New(),
		CVE:       "CVE-2026-31337",
		Exposures: []ProductExposure{exposure("gateway", "2.2.0")},
		CVSSBase:  &score,
		Awareness: awareAt(t, "2026-09-26T06:00:00Z"),
	}
	a, err := ResolveExposure(in, assessedAt)
	require.NoError(t, err)
	require.Len(t, a.Prioritised, 1)

	var hasGap bool
	for _, g := range a.Prioritised[0].Gaps {
		if g.Code == GapNoExploitationEvidence && g.Blocking {
			hasGap = true
		}
	}
	assert.True(t, hasGap, "a severe vulnerability nobody is exploiting must not be promoted by its score")

	// Compare against the same exposure WITH evidence, so the assertion is
	// about the evidence and not about an absolute score.
	withEvidence, err := ResolveExposure(ExposureInput{
		VulnID:    in.VulnID,
		CVE:       in.CVE,
		CVSSBase:  &score, // identical severity
		Exposures: []ProductExposure{exposure("gateway", "2.2.0")},
		Signals:   []ExploitationSignal{signal(EvidenceSourceCISAKEV, true)},
		Awareness: awareAt(t, "2026-09-26T06:00:00Z"),
	}, assessedAt)
	require.NoError(t, err)
	assert.Greater(t, a.Prioritised[0].AttentionRank, withEvidence.Prioritised[0].AttentionRank,
		"the same CVSS score must not place an unexploited vulnerability above an exploited one")
}

func TestExploitationEvidenceOutranksSeverityInTheAttentionQueue(t *testing.T) {
	score := 3.1                                // the vulnerability is only moderately severe throughout
	quiet := exposure("quiet-product", "1.0.0") // not attacked
	loud := exposure("loud-product", "4.0.0")   // actively attacked

	in := ExposureInput{
		VulnID:    uuid.New(),
		CVE:       "CVE-2026-31337",
		CVSSBase:  &score,
		Exposures: []ProductExposure{quiet, loud},
		// Product-scoped: exploitation is observed against the loud product
		// only, and must not be read as evidence against the quiet one.
		Signals:   []ExploitationSignal{scopedSignal(EvidenceSourceCISAKEV, "loud-product", true)},
		Awareness: awareAt(t, "2026-09-26T06:00:00Z"),
	}

	a, err := ResolveExposure(in, assessedAt)
	require.NoError(t, err)
	require.Len(t, a.Prioritised, 2)
	assert.Equal(t, "loud-product", a.Prioritised[0].ProductID,
		"the product actually under attack is reviewed first")
	assert.Contains(t, gapCodes(a.Prioritised[1].Gaps), GapNoExploitationEvidence,
		"the unattacked product is not treated as attacked")
}

// --- evidence strength is retained, not collapsed into a boolean -----------

func TestSignalStrengthIsOrderedAndPreserved(t *testing.T) {
	assert.Equal(t, SignalStrengthCorroborated, signal(EvidenceSourceCISAKEV, true).Strength())
	assert.Equal(t, SignalStrengthDirect, signal(EvidenceSourceInternalTelemetry, false).Strength())
	assert.Equal(t, SignalStrengthAuthoritative, signal(EvidenceSourceNationalCERT, false).Strength())
	assert.Equal(t, SignalStrengthUncorroborated, signal(EvidenceSourceEUVD, false).Strength())
}

func TestUnreferencedSignalsAreIgnored(t *testing.T) {
	// A signal with no reference is an assertion with nothing behind it.
	in := ExposureInput{
		VulnID:    uuid.New(),
		CVE:       "CVE-2026-31337",
		Exposures: []ProductExposure{exposure("gateway", "2.2.0")},
		Signals:   []ExploitationSignal{{Source: EvidenceSourceCISAKEV}},
		Awareness: awareAt(t, "2026-09-26T06:00:00Z"),
	}
	a, err := ResolveExposure(in, assessedAt)
	require.NoError(t, err)
	assert.Equal(t, SignalStrength(""), a.Prioritised[0].StrongestSignal)
}

// --- VEX is evidence, never an automatic exclusion ------------------------

func TestActiveNotAffectedVexIsSurfacedButDoesNotRemoveTheExposure(t *testing.T) {
	e := exposure("gateway", "2.2.0")
	e.VexStatements = []VexClaim{{
		StatementID:     uuid.New(),
		Status:          "active",
		Justification:   "vulnerable_code_not_in_execute_path",
		ImpactStatement: "the affected function is only reachable from the CLI",
		Confidence:      "high",
	}}

	in := ExposureInput{
		VulnID:    uuid.New(),
		CVE:       "CVE-2026-31337",
		Exposures: []ProductExposure{e},
		Signals:   []ExploitationSignal{signal(EvidenceSourceInternalTelemetry, true)},
		Awareness: awareAt(t, "2026-09-26T06:00:00Z"),
	}
	a, err := ResolveExposure(in, assessedAt)
	require.NoError(t, err)

	require.Len(t, a.Prioritised, 1, "a not_affected claim must not delete the exposure")
	assert.True(t, a.Prioritised[0].VexAssertsNotAffected)
	assert.Contains(t, a.Prioritised[0].RankRationale, "not_affected VEX")
	// It demotes the exposure rather than deleting it.
	assert.Greater(t, a.Prioritised[0].AttentionRank, 0)
}

func TestExpiredVexDoesNotCountAsAClaim(t *testing.T) {
	past := assessedAt.Add(-30 * 24 * time.Hour)
	e := exposure("gateway", "2.2.0")
	e.VexStatements = []VexClaim{{
		StatementID:   uuid.New(),
		Status:        "active",
		Justification: "component_not_present",
		ValidUntil:    &past,
	}}
	in := ExposureInput{
		VulnID:    uuid.New(),
		CVE:       "CVE-2026-31337",
		Exposures: []ProductExposure{e},
		Signals:   []ExploitationSignal{signal(EvidenceSourceCISAKEV, true)},
		Awareness: awareAt(t, "2026-09-26T06:00:00Z"),
	}
	a, err := ResolveExposure(in, assessedAt)
	require.NoError(t, err)
	assert.False(t, a.Prioritised[0].VexAssertsNotAffected,
		"a claim that expired last month says nothing about today")
}

func TestDraftVexIsNotAClaim(t *testing.T) {
	e := exposure("gateway", "2.2.0")
	e.VexStatements = []VexClaim{{
		StatementID:   uuid.New(),
		Status:        "draft",
		Justification: "component_not_present",
	}}
	in := ExposureInput{
		VulnID:    uuid.New(),
		CVE:       "CVE-2026-31337",
		Exposures: []ProductExposure{e},
		Signals:   []ExploitationSignal{signal(EvidenceSourceCISAKEV, true)},
		Awareness: awareAt(t, "2026-09-26T06:00:00Z"),
	}
	a, _ := ResolveExposure(in, assessedAt)
	assert.False(t, a.Prioritised[0].VexAssertsNotAffected,
		"a draft has not been asserted by anyone")
}

// --- the brief's questions, answered ------------------------------------

func TestEveryProductInstanceIsTrackedSeparately(t *testing.T) {
	// The same third-party component shipped in three products. Each is a
	// separate CRA question with a separate product identity, and collapsing
	// them into one report would lose which product was actually affected.
	in := ExposureInput{
		VulnID: uuid.New(),
		CVE:    "CVE-2026-31337",
		Exposures: []ProductExposure{
			exposure("gateway", "2.2.0"),
			exposure("analytics-agent", "0.9.1"),
			exposure("edge-controller", "5.1"),
		},
		Signals:   []ExploitationSignal{signal(EvidenceSourceCISAKEV, true)},
		Awareness: awareAt(t, "2026-09-26T06:00:00Z"),
	}
	a, err := ResolveExposure(in, assessedAt)
	require.NoError(t, err)
	require.Len(t, a.Prioritised, 3)

	products := map[string]bool{}
	for _, p := range a.Prioritised {
		products[p.ProductID] = true
		assert.Equal(t, "libfoo", p.ComponentName, "the upstream component is retained on every exposure")
	}
	assert.Len(t, products, 3)
}

func TestExistingReportsAreSurfacedForDeduplication(t *testing.T) {
	existing := uuid.New()
	in := ExposureInput{
		VulnID:          uuid.New(),
		CVE:             "CVE-2026-31337",
		Exposures:       []ProductExposure{exposure("gateway", "2.2.0")},
		Signals:         []ExploitationSignal{signal(EvidenceSourceCISAKEV, true)},
		Awareness:       awareAt(t, "2026-09-26T06:00:00Z"),
		ExistingReports: []uuid.UUID{existing},
	}
	a, err := ResolveExposure(in, assessedAt)
	require.NoError(t, err)
	assert.Equal(t, []uuid.UUID{existing}, a.AlreadyCovered,
		"an open report for this vulnerability must be visible so the same event is not filed twice")
}

// --- gaps are reported, not hidden ----------------------------------------

func TestUnknownReachabilityIsBlockingAndNotTreatedAsReachable(t *testing.T) {
	e := exposure("gateway", "2.2.0")
	e.Reachability = ReachabilityUnknown
	in := ExposureInput{
		VulnID: uuid.New(), CVE: "CVE-2026-31337",
		Exposures: []ProductExposure{e},
		Signals:   []ExploitationSignal{signal(EvidenceSourceCISAKEV, true)},
		Awareness: awareAt(t, "2026-09-26T06:00:00Z"),
	}
	a, _ := ResolveExposure(in, assessedAt)
	assert.Contains(t, gapCodes(a.Prioritised[0].Gaps), GapReachabilityUnknown)
	assert.False(t, ReachabilityUnknown.Known())
}

func TestInconclusiveReachabilityIsDistinctFromNotReachable(t *testing.T) {
	e := exposure("gateway", "2.2.0")
	e.Reachability = ReachabilityInconclusive
	in := ExposureInput{
		VulnID: uuid.New(), CVE: "CVE-2026-31337",
		Exposures: []ProductExposure{e},
		Signals:   []ExploitationSignal{signal(EvidenceSourceCISAKEV, true)},
		Awareness: awareAt(t, "2026-09-26T06:00:00Z"),
	}
	a, _ := ResolveExposure(in, assessedAt)
	assert.Contains(t, gapCodes(a.Prioritised[0].Gaps), GapReachabilityInconclusive)
	assert.False(t, ReachabilityInconclusive.Known(),
		"an inconclusive analysis is not a finding of not-reachable")
}

func TestStaleCompositionEvidenceIsFlagged(t *testing.T) {
	e := exposure("gateway", "2.2.0")
	e.LatestScanAt = assessedAt.AddDate(-2, 0, 0)
	in := ExposureInput{
		VulnID: uuid.New(), CVE: "CVE-2026-31337",
		Exposures: []ProductExposure{e},
		Signals:   []ExploitationSignal{signal(EvidenceSourceCISAKEV, true)},
		Awareness: awareAt(t, "2026-09-26T06:00:00Z"),
	}
	a, _ := ResolveExposure(in, assessedAt)
	assert.Contains(t, gapCodes(a.Prioritised[0].Gaps), GapStaleComposition)
}

func TestWeakComponentMatchIsFlagged(t *testing.T) {
	e := exposure("gateway", "2.2.0")
	e.MatchConfidence = "low"
	e.ComponentPURL = ""
	in := ExposureInput{
		VulnID: uuid.New(), CVE: "CVE-2026-31337",
		Exposures: []ProductExposure{e},
		Signals:   []ExploitationSignal{signal(EvidenceSourceCISAKEV, true)},
		Awareness: awareAt(t, "2026-09-26T06:00:00Z"),
	}
	a, _ := ResolveExposure(in, assessedAt)
	assert.Contains(t, gapCodes(a.Prioritised[0].Gaps), GapMatchConfidenceLow)
}

// --- ordering -------------------------------------------------------------

func TestExposuresAreOrderedByAttentionAndExplainThemselves(t *testing.T) {
	reachable := exposure("reachable", "1.0")
	unreachable := exposure("unreachable", "1.0")
	unreachable.Reachability = ReachabilityNotReachable

	in := ExposureInput{
		VulnID:    uuid.New(),
		CVE:       "CVE-2026-31337",
		Exposures: []ProductExposure{unreachable, reachable},
		Signals:   []ExploitationSignal{signal(EvidenceSourceCISAKEV, true)},
		Awareness: awareAt(t, "2026-09-26T06:00:00Z"),
	}
	a, err := ResolveExposure(in, assessedAt)
	require.NoError(t, err)
	require.Len(t, a.Prioritised, 2)
	assert.Equal(t, "reachable", a.Prioritised[0].ProductID)
	for _, p := range a.Prioritised {
		assert.NotEmpty(t, p.RankRationale, "every rank must be arguable in words")
	}
}

func TestResolverIsDeterministicForIdenticalInputs(t *testing.T) {
	in := ExposureInput{
		VulnID: uuid.New(), CVE: "CVE-2026-31337",
		Exposures: []ProductExposure{exposure("a", "1"), exposure("b", "1"), exposure("c", "1")},
		Signals:   []ExploitationSignal{signal(EvidenceSourceCISAKEV, true)},
		Awareness: awareAt(t, "2026-09-26T06:00:00Z"),
	}
	first, err := ResolveExposure(in, assessedAt)
	require.NoError(t, err)
	for i := 0; i < 5; i++ {
		again, err := ResolveExposure(in, assessedAt)
		require.NoError(t, err)
		for j := range first.Prioritised {
			assert.Equal(t, first.Prioritised[j].ProductID, again.Prioritised[j].ProductID)
		}
	}
}

func gapCodes(gaps []Gap) []string {
	out := make([]string, 0, len(gaps))
	for _, g := range gaps {
		out = append(out, g.Code)
	}
	return out
}
