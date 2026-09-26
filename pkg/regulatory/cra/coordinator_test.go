// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.

package cra

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCoordinatorSelectionRequiresBasisAndSelector(t *testing.T) {
	r := classifyAEV(t)
	now := mustTime(t, "2026-09-20T10:00:00Z")

	_, err := r.SelectCoordinator(Coordinator{CsirtID: "DE-CSIRT", Basis: SelectionBasisEstablishmentCountry, SelectedBy: "user:sec@example.eu"}, now)
	require.NoError(t, err)

	_, err = r.SelectCoordinator(Coordinator{CsirtID: "", Basis: SelectionBasisEstablishmentCountry, SelectedBy: "u"}, now)
	require.ErrorIs(t, err, ErrCoordinatorUndetermined)

	_, err = r.SelectCoordinator(Coordinator{CsirtID: "DE-CSIRT", Basis: "vibes", SelectedBy: "u"}, now)
	require.Error(t, err, "an unrecognised basis cannot be recorded")

	_, err = r.SelectCoordinator(Coordinator{CsirtID: "DE-CSIRT", Basis: SelectionBasisEstablishmentCountry}, now)
	require.Error(t, err, "an unattributed selection is not a selection")
}

func TestManualOverrideRequiresWrittenJustification(t *testing.T) {
	r := classifyAEV(t)
	now := mustTime(t, "2026-09-20T10:00:00Z")

	_, err := r.SelectCoordinator(Coordinator{
		CsirtID: "FR-CSIRT", Basis: SelectionBasisManualOverride, SelectedBy: "user:sec@example.eu",
	}, now)
	require.Error(t, err, "an unexplained override is the weakest possible provenance")

	_, err = r.SelectCoordinator(Coordinator{
		CsirtID: "FR-CSIRT", Basis: SelectionBasisManualOverride, SelectedBy: "user:sec@example.eu",
		Justification: "affected users are concentrated in France; the affected-user CSIRT is better placed to support them",
	}, now)
	require.NoError(t, err)
}

func TestCoordinatorOverrideIsAudited(t *testing.T) {
	r := classifyAEV(t)
	now := mustTime(t, "2026-09-20T10:00:00Z")

	r, err := r.SelectCoordinator(Coordinator{
		CsirtID: "DE-CSIRT", Country: "DE", Basis: SelectionBasisEstablishmentCountry,
		SelectedBy: "user:sec@example.eu", Justification: "establishment is in Berlin",
	}, now)
	require.NoError(t, err)
	require.Nil(t, r.Coordinator.Overridden, "a first selection has nothing to override")

	r, err = r.SelectCoordinator(Coordinator{
		CsirtID: "FR-CSIRT", Country: "FR", Basis: SelectionBasisManualOverride,
		SelectedBy: "user:sec@example.eu", Justification: "all confirmed victims are in France",
	}, mustTime(t, "2026-09-20T11:00:00Z"))
	require.NoError(t, err)

	require.NotNil(t, r.Coordinator.Overridden)
	assert.Equal(t, "DE-CSIRT", r.Coordinator.Overridden.CsirtID)
	assert.Equal(t, "DE", r.Coordinator.Overridden.Country)
	assert.Equal(t, "all confirmed victims are in France", r.Coordinator.Overridden.Reason)
	assert.Equal(t, "user:sec@example.eu", r.Coordinator.Overridden.By)
}

func TestCandidateCoordinatorsNeverDefaultsToENISA(t *testing.T) {
	// Every candidate carries a named national CSIRT and a stated basis. A
	// default would mean filing to the wrong authority, which loses the report.
	out := CandidateCoordinators(OrganisationProfile{
		ManufacturerName:     "Example GmbH",
		EstablishmentCountry: "DE",
		HasEUEstablishment:   true,
	})
	require.NotEmpty(t, out)
	for _, c := range out {
		assert.NotEqual(t, "ENISA", c.CsirtID)
		assert.NotEqual(t, "EU", c.CsirtID)
		assert.True(t, c.Basis.Valid())
	}
	assert.Equal(t, "DE-CSIRT", out[0].CsirtID)
}

func TestNonEUManufacturerIsRoutedThroughItsRepresentative(t *testing.T) {
	out := CandidateCoordinators(OrganisationProfile{
		ManufacturerName:     "Example Inc",
		EstablishmentCountry: "US",
		HasEUEstablishment:   false,
		EURepresentative:     &EURepresentative{Name: "Example EU Rep BV", Country: "NL"},
	})
	require.Len(t, out, 1)
	assert.Equal(t, "NL-CSIRT", out[0].CsirtID)
	assert.Equal(t, SelectionBasisEURepresentative, out[0].Basis)
}

func TestNonEUManufacturerWithNoRepresentativeYieldsNoCandidate(t *testing.T) {
	// No silent fallback. An empty shortlist forces the human to supply the
	// missing metadata rather than quietly filing to the wrong place.
	out := CandidateCoordinators(OrganisationProfile{EstablishmentCountry: "US", HasEUEstablishment: false})
	assert.Empty(t, out)
}

func TestMultipleEstablishmentsAppearBeforeThePrimaryOne(t *testing.T) {
	out := CandidateCoordinators(OrganisationProfile{
		EstablishmentCountry:   "DE",
		EstablishmentCountries: []string{"FR", "NL"},
		HasEUEstablishment:     true,
	})
	require.Len(t, out, 3)
	assert.Equal(t, "FR-CSIRT", out[0].CsirtID)
	assert.Equal(t, "NL-CSIRT", out[1].CsirtID)
	assert.Equal(t, "DE-CSIRT", out[2].CsirtID)
}

func TestCoordinatorSelectionIsTimestamped(t *testing.T) {
	r := classifyAEV(t)
	now := mustTime(t, "2026-09-20T10:00:00Z")
	r, err := r.SelectCoordinator(Coordinator{
		CsirtID: "DE-CSIRT", Basis: SelectionBasisEstablishmentCountry, SelectedBy: "u",
	}, now)
	require.NoError(t, err)
	require.NotNil(t, r.Coordinator.SelectedAt)
	assert.True(t, r.Coordinator.SelectedAt.Equal(now), "an untimed selection is stamped from the supplied clock")

	// With no clock at all the selection is still stamped — an untimed
	// selection is not permitted to exist.
	r, err = r.SelectCoordinator(Coordinator{
		CsirtID: "FR-CSIRT", Basis: SelectionBasisAffectedUsers, SelectedBy: "u",
	}, time.Time{})
	require.NoError(t, err)
	require.NotNil(t, r.Coordinator.SelectedAt)
	assert.False(t, r.Coordinator.SelectedAt.IsZero())
}
