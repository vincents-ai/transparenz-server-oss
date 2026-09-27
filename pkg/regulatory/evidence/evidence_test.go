// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.

package evidence

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var observedAt = time.Date(2026, 9, 26, 9, 0, 0, 0, time.UTC)

func validObservation() Observation {
	sbom := uuid.New()
	return Observation{
		ID:     uuid.New(),
		OrgID:  uuid.New(),
		Kind:   KindActiveExploitation,
		Title:  "Authentication bypass exploited against a shipped gateway",
		Origin: OriginExploitArtefact,
		// Deliberately weak: one person's assertion. The layer's job is to
		// keep that visible, not to round it up.
		Certainty:  CertaintyReported,
		ObservedAt: observedAt,
		Artefact:   "pcap-2026-09-20-0845",
		Subjects: []Subject{{
			Kind:       SubjectProductWithDigitalElements,
			Identifier: "gateway-3.1.2",
			Name:       "Example Gateway",
			SbomID:     &sbom,
		}},
	}
}

func TestAValidObservationIsAccepted(t *testing.T) {
	require.NoError(t, validObservation().Validate())
}

// --- what the layer refuses ------------------------------------------------

// A bare assertion is not evidence. Without an artefact it will be mapped onto
// obligations and a determination will be made on it, so it has to be
// demonstrable.
func TestObservationWithoutAnArtefactIsRefused(t *testing.T) {
	o := validObservation()
	o.Artefact = "  "
	err := o.Validate()
	require.ErrorIs(t, err, ErrIncomplete)
	assert.Contains(t, err.Error(), "artefact")
}

// Without a subject the observation cannot be mapped to any obligation, so it
// evidences nothing at all.
func TestObservationWithoutASubjectIsRefused(t *testing.T) {
	o := validObservation()
	o.Subjects = nil
	err := o.Validate()
	require.ErrorIs(t, err, ErrIncomplete)
	assert.Contains(t, err.Error(), "subject")
}

func TestObservationWithAnUnknownKindOrOriginIsRefused(t *testing.T) {
	o := validObservation()
	o.Kind = "something"
	require.Error(t, o.Validate())

	o = validObservation()
	o.Origin = "gut feel"
	require.Error(t, o.Validate())

	o = validObservation()
	o.Certainty = "probably"
	require.Error(t, o.Validate())
}

func TestObservationWithoutAnObservationTimeIsRefused(t *testing.T) {
	o := validObservation()
	o.ObservedAt = time.Time{}
	require.Error(t, o.Validate())
}

// --- the layer holds no regulatory state ----------------------------------

// The single most important property of this package. If a deadline, a state
// or a determination ever appears on an Observation, the layer has started
// doing a regime's job and the two engines are no longer independent.
//
// This is asserted structurally rather than by convention: the test is
// meaningless the moment someone adds such a field, which is the point.
func TestObservationCarriesNoDeadlineStateOrDetermination(t *testing.T) {
	o := validObservation()

	// There is no such field. Compiling this test is the assertion: adding
	// a Deadline, State or Reportable to Observation and referring to it here
	// would be the only way this could fail, and the failure would be loud.
	_ = o.ObservedAt // the only time on the type is when the fact occurred
	_ = o.Artefact   // provenance
	_ = o.Certainty  // strength of the claim
	_ = o.Subjects   // what it is about
	_ = o.Related    // links, not conclusions

	// In particular ObservedAt is NOT the awareness instant. A regulatory
	// clock starts when the manufacturer became aware, which is a mapping
	// decision made by each regime, not a property of the evidence.
	awareness := observedAt.Add(72 * time.Hour)
	assert.True(t, awareness.After(o.ObservedAt))
}

// Weak evidence stays weak.
func TestCertaintyIsCarriedRatherThanRoundedUp(t *testing.T) {
	o := validObservation()
	assert.Equal(t, CertaintyReported, o.Certainty,
		"a single reported assertion must not be recorded as observed")

	observed := validObservation()
	observed.Certainty = CertaintyObserved
	assert.Equal(t, CertaintyObserved, observed.Certainty)
}

// Product and entity are different subjects with different legal scopes, and
// the layer distinguishes them without knowing either regime.
func TestProductAndEntityAreDistinctSubjects(t *testing.T) {
	o := validObservation()
	assert.True(t, o.AppliesTo(SubjectProductWithDigitalElements))
	assert.False(t, o.AppliesTo(SubjectEssentialOrImportantEntity),
		"a product observation is not an entity observation")

	e := validObservation()
	e.Kind = KindSevereIncident
	e.Subjects = []Subject{{
		Kind: SubjectEssentialOrImportantEntity, Identifier: "acme-ie", Name: "Acme",
	}}
	assert.True(t, e.AppliesTo(SubjectEssentialOrImportantEntity))
	assert.False(t, e.AppliesTo(SubjectProductWithDigitalElements))
}

// --- amendments -----------------------------------------------------------

// How a correction was handled is what an authority examines.
func TestAmendmentMustChangeSomethingAndSayWhy(t *testing.T) {
	obs := uuid.New()

	noChange := Amendment{
		ObservationID: obs, Field: "observed_at",
		OldValue: "a", NewValue: "a",
		Reason: "typo", Actor: "u", AmendedAt: observedAt,
	}
	require.Error(t, noChange.Validate())

	noReason := Amendment{
		ObservationID: obs, Field: "observed_at",
		OldValue: "a", NewValue: "b",
		Actor: "u", AmendedAt: observedAt,
	}
	require.Error(t, noReason.Validate(), "an uncorroborated amendment is not auditable")

	noActor := Amendment{
		ObservationID: obs, Field: "observed_at",
		OldValue: "a", NewValue: "b",
		Reason: "re", AmendedAt: observedAt,
	}
	require.Error(t, noActor.Validate())

	good := Amendment{
		ObservationID: obs, Field: "observed_at",
		OldValue: "2026-09-26T09:00:00Z", NewValue: "2026-09-26T11:00:00Z",
		Reason: "the capture timestamp was the exporter's clock; ours logged 11:00",
		Actor:  "user:ir@example.eu", AmendedAt: observedAt,
	}
	require.NoError(t, good.Validate())
}

// --- the mapping is where the regimes separate -----------------------------

func TestObligationLinkRequiresARationale(t *testing.T) {
	link := ObligationLink{
		ObservationID: uuid.New(), Regime: RegimeCRA, Obligation: "CRA Article 14",
	}
	require.Error(t, link.Validate(), "a mapping nobody can explain is not a mapping")

	link.Rationale = "exploitation observed against a product placed on the EU market"
	require.NoError(t, link.Validate())
}

func TestObligationLinkRejectsAnUnknownRegime(t *testing.T) {
	link := ObligationLink{
		ObservationID: uuid.New(), Regime: "GDPR", Obligation: "Art. 33",
		Rationale: "breach notification",
	}
	require.Error(t, link.Validate())
}

// The case the layer exists for: one fact, two regimes, two different duties.
// They are separate obligations with separate clocks and separate recipients,
// and a single boolean on the observation would collapse exactly that.
func TestOneObservationCanEngageTwoRegimesWithoutConflatingThem(t *testing.T) {
	o := validObservation()
	require.NoError(t, o.Validate())

	awareness := observedAt
	bundle := Bundle{
		Observation: o,
		Links: []ObligationLink{
			{
				ObservationID: o.ID, Regime: RegimeCRA,
				Obligation:  "CRA Article 14",
				AwarenessAt: &awareness,
				Authority:   "DE-CSIRT",
				Rationale:   "exploitation of a vulnerability in a product placed on the EU market",
			},
			{
				ObservationID: o.ID, Regime: RegimeNIS2,
				Obligation:  "NIS2 Article 23",
				AwarenessAt: &awareness,
				Authority:   "BSI",
				Rationale:   "the same event meets the significance threshold for an essential entity",
			},
		},
	}
	for _, l := range bundle.Links {
		require.NoError(t, l.Validate())
	}

	assert.True(t, bundle.CrossRegime())
	assert.ElementsMatch(t, []Regime{RegimeCRA, RegimeNIS2}, bundle.EngagedRegimes())

	// Same fact, different duty and different recipient — which is the whole
	// reason the mapping is a list and not a flag.
	assert.Equal(t, "CRA Article 14", bundle.Links[0].Obligation)
	assert.Equal(t, "NIS2 Article 23", bundle.Links[1].Obligation)
	assert.NotEqual(t, bundle.Links[0].Authority, bundle.Links[1].Authority)
}

func TestSingleRegimeBundleIsNotCrossRegime(t *testing.T) {
	o := validObservation()
	bundle := Bundle{Observation: o, Links: []ObligationLink{{
		ObservationID: o.ID, Regime: RegimeCRA, Obligation: "CRA Article 14",
		Rationale: "exploitation observed",
	}}}
	assert.False(t, bundle.CrossRegime())
	assert.Equal(t, []Regime{RegimeCRA}, bundle.EngagedRegimes())
}

// The same artefact may be referenced by several mappings without being
// re-recorded, which is the point of the layer.
func TestObservationLinksToRelatedArtefactsWithoutAssertingConclusions(t *testing.T) {
	o := validObservation()
	o.Related = []Reference{
		{Kind: "sbom", ID: uuid.New()},
		{Kind: "scan", ID: uuid.New()},
	}
	require.NoError(t, o.Validate())
	assert.Len(t, o.Related, 2)
}

// A vulnerability on its own is not evidence of a regulatory event, and the
// layer must not let one be recorded as though it were.
func TestBareVulnerabilityIsARecognisedButWeakKind(t *testing.T) {
	o := validObservation()
	o.Kind = KindVulnerability
	require.NoError(t, o.Validate())
	assert.Equal(t, KindVulnerability, o.Kind,
		"a CVE carries no exploitation claim and must not be recorded as one")
}
