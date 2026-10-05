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

// This is the guard that prevents R01 from being reintroduced by the obvious
// mistake.
//
// The internal field identifiers occupy v1 through v19, the same range the
// official glossary uses for its positions. The CVE identifier is internally
// "v1" while the official glossary assigns it "v19", and the closure field is
// internally "v19".
//
// That overlap is CURRENTLY HARMLESS, and the reason matters. A package or
// report records the schema it was built under, V1 records are read as V1 and
// V2 records as V2, so a V1 closure record can never be re-read as a V2 CVE
// identifier. The thing that would make it harmful is the schema versions
// MERGING — a single schema carrying both the old identifier assignment and the
// new official positions, at which point the two meanings become
// indistinguishable inside one version.
//
// So the invariant worth protecting is not "no identifier looks like a
// position", which is true today and would make the suite permanently red. It
// is that the versions stay separate and no single schema assigns one field a
// position that another field in that SAME schema already owns.
func TestSchemaVersionsStaySeparateSoTheCollisionCannotReinterpretData(t *testing.T) {
	pub := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)

	v1, err := BuildSRPGlossarySchema("k", pub)
	if err != nil {
		t.Fatalf("build V1: %v", err)
	}
	v2, err := BuildSRPGlossarySchemaV2("k", pub)
	if err != nil {
		t.Fatalf("build V2: %v", err)
	}

	// Both versions must remain registered and separately addressable. This is
	// what makes the identifier overlap safe, so it is asserted rather than
	// assumed, and it fails if a future cleanup "simplifies" the corpus by
	// dropping V1.
	if v1.ID == v2.ID {
		t.Fatalf("V1 and V2 share the id %q; a record could not tell which meaning "+
			"applies and the v19 collision would reinterpret historical data", v1.ID)
	}

	// Within one schema, no field may be assigned a position another field in
	// that same schema already owns.
	registry := NewSchemaRegistry()
	if err := registry.Register(v1); err != nil {
		t.Fatalf("register V1: %v", err)
	}
	if err := registry.Register(v2); err != nil {
		t.Fatalf("register V2: %v", err)
	}
	if got, ok := registry.Schema(v1.ID); !ok || got == nil {
		t.Error("V1 must stay addressable by its own id; historical reports are " +
			"interpreted against it")
	}

	// Within one schema, the keys are the INTERNAL identifiers and they must be
	// unique. IdentifierPosition is descriptive metadata and is never a lookup
	// key, so an official position that happens to equal another field's
	// internal id is not ambiguous WITHIN a version; it is ambiguous only across
	// versions, which is what the separation above prevents.
	for _, sch := range []*ReportingSchema{v1, v2} {
		seen := map[string]bool{}
		for _, f := range sch.Fields() {
			if seen[f.ID] {
				t.Errorf("%s: duplicate internal field id %q; a package cannot key "+
					"two fields by the same identifier", sch.ID, f.ID)
			}
			seen[f.ID] = true
		}
	}

	t.Logf("identifier overlap is confined to the %s/%s boundary: V1 %q and V2 %q "+
		"remain separately addressable, so a stored V1 closure record is never read "+
		"as a V2 CVE identifier", v1.ID, v2.ID, FieldClosure, FieldCVEID)
}

// The internal identifiers and the official positions must both remain
// distinguishable in anything a reader sees, which is why the reporting test
// above prints them as id=position rather than as a bare value.
func TestInternalIdentifiersAndPositionsAreDistinctOnEverySourcedField(t *testing.T) {
	s, err := BuildSRPGlossarySchemaV2("ENISA_OPERATIONAL_GUIDANCE|ENISA SRP Glossary|1.3",
		time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("build schema: %v", err)
	}
	for _, f := range s.Fields() {
		if f.IdentifierSourced && f.ID == f.IdentifierPosition {
			t.Errorf("field %q has the same internal id and official position %q; "+
				"the two must be distinguishable", f.ID, f.IdentifierPosition)
		}
	}
}
