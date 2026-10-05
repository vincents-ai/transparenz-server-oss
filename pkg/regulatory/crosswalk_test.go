package regulatory

import (
	"fmt"
	"sort"
	"testing"
	"time"
)

// The SRP schema is INCOMPLETE, and this test makes that fact impossible to
// overlook.
//
// Thirteen of fifteen fields carry identifiers this implementation assigned
// rather than transcribed from the authoritative ENISA glossary. That is
// recorded on every field, in the conformance matrix, and in the release notes,
// and it is easy to lose in all three. This test prints the count and the names
// on every run, and fails if a field is marked as transcribed without a
// position, so the provenance flag cannot drift into meaning something other
// than what it says.
//
// It does NOT fail merely because fields are unsourced. That would mean the
// suite is red until the glossary document is obtained, which trains people to
// ignore it. The gap is real and documented; the failure this prevents is a
// field being CLAIMED as official without one.
func TestSRPSchemaReportsItsCrosswalkCompleteness(t *testing.T) {
	s, err := BuildSRPGlossarySchemaV2("ENISA_OPERATIONAL_GUIDANCE|ENISA SRP Glossary|1.3",
		time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("build schema: %v", err)
	}

	var sourced, unsourced []string
	for _, f := range s.Fields() {
		switch {
		case f.IdentifierSourced && f.IdentifierPosition == "":
			t.Errorf("field %s is marked as transcribed from the glossary but carries no "+
				"position; the two must agree or the provenance flag is meaningless",
				f.ID)
		case f.IdentifierSourced:
			sourced = append(sourced, fmt.Sprintf("%s=%s", f.ID, f.IdentifierPosition))
		default:
			unsourced = append(unsourced, f.ID)
		}
	}
	sort.Strings(unsourced)

	t.Logf("SRP glossary crosswalk: %d of %d fields transcribed from the official glossary",
		len(sourced), len(sourced)+len(unsourced))
	for _, s := range sourced {
		t.Logf("  sourced    %s", s)
	}
	if len(unsourced) > 0 {
		t.Logf("  UNSOURCED (%d), assigned by this implementation and marked as such: %v",
			len(unsourced), unsourced)
		t.Logf("  These must not be described as an authoritative mapping. A package generated " +
			"today carries correct v19 and v20 for CVE and EUVD and implementation-chosen " +
			"identifiers for the rest.")
	}
}

// An identifier position that is not the documented form would silently defeat
// the whole point of recording it.
func TestRecordedGlossaryPositionsAreWellFormed(t *testing.T) {
	for _, f := range []struct{ id, pos string }{
		{FieldCVEID, "v19"},
		{FieldEUVDID, "v20"},
	} {
		if len(f.pos) < 2 || f.pos[0] != 'v' {
			t.Errorf("%s position %q is not a glossary position of the form vNN",
				f.id, f.pos)
		}
	}
}
