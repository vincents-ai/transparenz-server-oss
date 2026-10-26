package regulatory

import (
	"fmt"
	"regexp"
	"sort"
	"testing"
	"time"
)

// The SRP schema's crosswalk state, printed on every run so it cannot be lost in
// a document nobody opens.
//
// The history matters here. V2 carried thirteen of fifteen identifiers this
// implementation assigned rather than transcribed, and this test existed to make
// that impossible to overlook until the glossary was obtained. It now reports the
// v1.6 schema, which is a transcription: every field sourced, none assigned. V2's
// state is still reported, because a report filed under V2 was filed against
// those identifiers and the record has to stay readable.
//
// The failure this test prevents is unchanged: a field CLAIMED as official
// without a position behind it.
func TestSRPSchemaReportsItsCrosswalkCompleteness(t *testing.T) {
	s, err := BuildSRPGlossaryV16Schema("ENISA_OPERATIONAL_GUIDANCE|ENISA SRP Glossary|1.6",
		time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC))
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

	t.Logf("SRP glossary crosswalk (%s): %d of %d fields transcribed from the official glossary",
		s.ID, len(sourced), len(sourced)+len(unsourced))
	if len(unsourced) > 0 {
		t.Logf("  UNSOURCED (%d), assigned by this implementation and marked as such: %v",
			len(unsourced), unsourced)
		t.Logf("  These must not be described as an authoritative mapping.")
	} else {
		t.Logf("  complete: every field carries the position the published glossary assigns it")
	}

	// The current schema is a transcription, so an unsourced field appearing in
	// it is a regression, not a known gap. This is the line that was deliberately
	// absent while the glossary was unobtainable; now that it is retained, absence
	// of provenance is a defect.
	if len(unsourced) > 0 {
		t.Errorf("%s carries %d fields whose identifier this implementation assigned; "+
			"the v1.6 glossary is retained in this package and every position is transcribable",
			s.ID, len(unsourced))
	}

	// V2's state is reported for the historical record rather than asserted.
	v2, err := BuildSRPGlossarySchemaV2("ENISA_OPERATIONAL_GUIDANCE|ENISA SRP Glossary|1.3",
		time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("build V2: %v", err)
	}
	var v2Sourced int
	for _, f := range v2.Fields() {
		if f.IdentifierSourced {
			v2Sourced++
		}
	}
	t.Logf("%s (superseded, retained for reports filed under it): %d of %d identifiers sourced",
		v2.ID, v2Sourced, len(v2.Fields()))
}

// An identifier position that is not the documented form would silently defeat
// the whole point of recording it.
func TestRecordedGlossaryPositionsAreWellFormed(t *testing.T) {
	// Checked against the schema's own fields rather than against a hardcoded
	// pair. The earlier form asserted two literals, so it would have passed even
	// if every position in the schema were malformed.
	s, err := BuildSRPGlossaryV16Schema("k", time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("build schema: %v", err)
	}

	// The published position forms: a bare decimal for the common fields
	// (with "7a" as the one lettered variant), "vNN"/"vNNa" for AEV, "iNN"
	// for severe incidents, and two decimal case-management positions.
	wellFormed := regexp.MustCompile(`^([0-9]{1,2}[a-z]?|v[0-9]{2}[a-z]?|i[0-9]{2})$`)
	checked := 0
	for _, f := range s.Fields() {
		if !f.IdentifierSourced {
			continue
		}
		checked++
		if !wellFormed.MatchString(f.IdentifierPosition) {
			t.Errorf("%s position %q is not a published glossary position form", f.ID, f.IdentifierPosition)
		}
	}
	if checked == 0 {
		t.Fatal("no sourced positions were checked; the assertion above would pass vacuously")
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

	// The v1.6 schema deliberately reverses that arrangement. Because it was
	// transcribed after the glossary was in hand, it keys its fields by the
	// published identifiers themselves, so id and position converge. That is not
	// a regression of the V2 invariant — the invariant existed because V2's keys
	// were inherited from an earlier, wrong assignment. Where the key and the
	// position differ, the separation must hold; where the key IS the published
	// position, there is nothing to distinguish.
	v16, err := BuildSRPGlossaryV16Schema("k", time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("build v1.6: %v", err)
	}
	for _, f := range v16.Fields() {
		if !f.IdentifierSourced {
			t.Errorf("v1.6 field %q is not sourced; the schema is a transcription and every "+
				"field must say which published position it came from", f.ID)
			continue
		}
		if f.ID != f.IdentifierPosition {
			t.Errorf("v1.6 field %q carries position %q; this schema keys fields by the "+
				"published identifier, so the two must agree", f.ID, f.IdentifierPosition)
		}
	}
}
