// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.

package cra

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validFilingFacts() FilingFacts {
	return FilingFacts{
		ManufacturerName: "Example Manufacturing GmbH",
		ProductVersion:   "4.0 to 4.2.1",
		MemberStates:     []string{"DE", "NL"},
	}
}

func TestValidFilingFactsAreAccepted(t *testing.T) {
	require.NoError(t, validFilingFacts().Validate())
}

// Every refusal here is one the SRP form would make later, with a human on a
// 24-hour deadline, so making it at the point of recording is the benefit.
func TestFilingFactsRefuseWhatTheFormWouldRefuse(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*FilingFacts)
		want   string
	}{
		{"no manufacturer", func(f *FilingFacts) { f.ManufacturerName = "  " }, "legal person"},
		{"manufacturer too long", func(f *FilingFacts) { f.ManufacturerName = strings.Repeat("x", 256) }, "255"},
		{"no product version", func(f *FilingFacts) { f.ProductVersion = "" }, "product version"},
		{"product version too long", func(f *FilingFacts) { f.ProductVersion = strings.Repeat("x", 256) }, "255"},
		{"no member state", func(f *FilingFacts) { f.MemberStates = nil }, "Member State"},
		{"a country name rather than a code", func(f *FilingFacts) { f.MemberStates = []string{"Germany"} }, "alpha-2"},
		{"a three-letter code", func(f *FilingFacts) { f.MemberStates = []string{"DEU"} }, "alpha-2"},
		{"a duplicate", func(f *FilingFacts) { f.MemberStates = []string{"DE", "DE"} }, "twice"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := validFilingFacts()
			tc.mutate(&f)
			err := f.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
			assert.ErrorIs(t, err, ErrInvalidReport, "a bad fact is a report error, not a new error class")
		})
	}
}

// Lowercase is a typing habit, not a statement, so it is normalised rather than
// refused; an unrecognisable code is a different matter and is refused above.
func TestFilingFactsNormaliseRatherThanFightTheFiler(t *testing.T) {
	got := FilingFacts{
		ManufacturerName: "  Example Manufacturing GmbH  ",
		ProductVersion:   " 4.0 to 4.2.1 ",
		MemberStates:     []string{"de", " NL ", "DE", ""},
	}.Normalised()

	assert.Equal(t, "Example Manufacturing GmbH", got.ManufacturerName)
	assert.Equal(t, "4.0 to 4.2.1", got.ProductVersion)
	assert.Equal(t, []string{"DE", "NL"}, got.MemberStates,
		"codes are uppercased, trimmed and de-duplicated, and blanks dropped")

	require.NoError(t, got.Validate())
}

// Normalising must not rescue a value that is simply wrong: the code shape is
// still enforced after normalisation.
func TestNormalisingDoesNotRescueAnInvalidCode(t *testing.T) {
	got := FilingFacts{
		ManufacturerName: "Example Manufacturing GmbH",
		ProductVersion:   "4.0",
		MemberStates:     []string{"germany"},
	}.Normalised()
	require.Error(t, got.Validate())
}
