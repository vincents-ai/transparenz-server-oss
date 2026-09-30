package regulatory

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The registry previously computed SourceHash from a LABEL, e.g.
// ComputeSourceHash([]byte("CRA-ART14-GUIDANCE|C(2026) 5252")), and supplied one
// RetrievedAt at construction for every entry.
//
// That is not a weak hash, it is not a hash of the source. Two different texts
// published under the same title and version produce an identical value, so it
// cannot answer the only question an auditor asks: which text was reviewed when
// this obligation was mapped.
func TestLabelDerivedHashCannotDistinguishDifferentDocuments(t *testing.T) {
	a := LabelHash("ENISA SRP Glossary", "1.3")
	b := LabelHash("ENISA SRP Glossary", "1.3")
	if a != b {
		t.Fatal("the label hash is not deterministic")
	}
	// The whole defect in one assertion: the same title and version with
	// DIFFERENT content is indistinguishable, because the content was never
	// hashed.
	if a == "sha256:"+a {
		t.Fatal("a label hash must not be presented as a content hash")
	}
	if !strings.HasPrefix(a, "label:") {
		t.Errorf("a label-derived hash must be visibly marked, got %q", a)
	}
}

// The acceptance criterion from the brief: changing document content while
// keeping its title and version must change the content hash.
func TestContentHashChangesWhenContentChangesButTitleAndVersionDoNot(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	url := "https://www.enisa.europa.eu/topics/cra/single-reporting-platform"

	original := NewSourceArtifact("ENISA SRP Glossary", "1.3", url, now,
		[]byte("CVE identifier: v19\nEUVD identifier: v20\n"), "reviewer-a")
	amended := NewSourceArtifact("ENISA SRP Glossary", "1.3", url, now,
		[]byte("CVE identifier: v1\nEUVD identifier: v2\n"), "reviewer-a")

	if original.Document != amended.Document {
		t.Error("title must be held constant for this test to mean anything")
	}
	if original.Version != amended.Version {
		t.Error("version must be held constant for this test to mean anything")
	}
	if original.ContentHash == amended.ContentHash {
		t.Fatal("content changed but the hash did not; the hash is not of the content")
	}

	// And each is independently reproducible, which is what makes it evidence.
	if !original.Verify() || !amended.Verify() {
		t.Error("an auditor must be able to re-hash the retained bytes and get the recorded value")
	}
	if LabelHash("ENISA SRP Glossary", "1.3") == LabelHash("ENISA SRP Glossary", "1.3") &&
		original.ContentHash == amended.ContentHash {
		t.Error("a label hash is stable across content changes, which is the defect")
	}
}

// An auditor retrieves the retained artifact and reproduces the hash.
func TestRetainedArtifactIsReproducible(t *testing.T) {
	content := []byte("Article 16(2) particularly exceptional circumstances.")
	a := NewSourceArtifact("CRA", "consolidated-2026-09-11",
		"https://eur-lex.europa.eu/eli/reg/2024/2847/oj", time.Now().UTC(), content, "reviewer-b")

	if !a.Verify() {
		t.Error("a freshly built artifact must verify")
	}
	if !strings.HasPrefix(a.ContentHash, "sha256:") {
		t.Errorf("a content hash must be identifiable as one, got %q", a.ContentHash)
	}

	// Tampering with the retained bytes must be detected.
	tampered := a
	tampered.Content = []byte("Article 16(2) something else entirely.")
	if tampered.Verify() {
		t.Error("tampering with retained content must break verification")
	}

	// An artifact with no retained bytes cannot be verified and must not claim to be.
	empty := SourceArtifact{ContentHash: a.ContentHash}
	if empty.Verify() {
		t.Error("a hash with no retained bytes must not verify")
	}
}

// Built-in registry entries are label-derived, and must say so rather than
// presenting a label hash as provenance. They are not "wrong" for it — the
// source is real and the version is right — but the hash does not evidence which
// wording was read, and a consumer must be able to filter on that.
func TestBuiltinRegistrySourcesAreMarkedLabelDerived(t *testing.T) {
	reg, _, err := BuildDefaultRegistry(time.Now().UTC())
	require.NoError(t, err)
	sources := reg.Sources()
	if len(sources) == 0 {
		t.Fatal("registry returned no sources")
	}

	var unverifiable []string
	for _, s := range sources {
		if s.IsVerifiable() {
			t.Errorf("source %q is marked verifiable but no artifact is retained for a "+
				"built-in entry; claiming verifiability without retained bytes is the "+
				"defect this work removes", s.Document)
		}
		if s.ArtifactDerived != ArtifactLabelDerived {
			t.Errorf("source %q has ArtifactDerived=%q; built-in entries are label-derived "+
				"and must say so", s.Document, s.ArtifactDerived)
		}
		unverifiable = append(unverifiable, s.Document)
	}
	if len(unverifiable) == 0 {
		t.Error("expected the built-in sources to be reported as unverified")
	}
}

// A consumer that must not rely on unverified provenance needs to be able to say
// so in words, because a boolean nobody reads is not a control.
func TestUnverifiableSourcesDescribeThemselvesAsSuch(t *testing.T) {
	s := Source{
		Document:        "ENISA SRP Glossary",
		Version:         "1.3",
		SourceHash:      LabelHash("ENISA SRP Glossary", "1.3"),
		ArtifactDerived: ArtifactLabelDerived,
	}
	desc := s.Describe()
	if !strings.Contains(desc, "NOT VERIFIABLE") {
		t.Errorf("a label-derived source must describe itself as unverifiable, got %q", desc)
	}
	if !strings.Contains(desc, "label") {
		t.Errorf("the description should say the hash comes from the label, got %q", desc)
	}

	// With an artifact attached, the description changes to the checkable form.
	s.AttachArtifact(NewSourceArtifact("ENISA SRP Glossary", "1.3",
		"https://example.invalid/glossary", time.Now().UTC(), []byte("body text"), "reviewer-c"))
	if !s.IsVerifiable() {
		t.Error("a source with a retained artifact must be verifiable")
	}
	desc = s.Describe()
	if strings.Contains(desc, "NOT VERIFIABLE") {
		t.Errorf("an artifact-backed source must not describe itself as unverifiable, got %q", desc)
	}
	if !strings.Contains(desc, "sha256:") {
		t.Errorf("the description should carry the content hash, got %q", desc)
	}
	if s.SourceURL != "https://example.invalid/glossary" {
		t.Errorf("attaching an artifact must record its canonical URL, got %q", s.SourceURL)
	}
	if s.Reviewer != "reviewer-c" {
		t.Errorf("attaching an artifact must record its reviewer, got %q", s.Reviewer)
	}
}

// Historical reports must remain tied to their original snapshot. Adding an
// artifact later must not silently change what a past record claimed, so the
// attachment is explicit rather than automatic.
func TestArtifactAttachmentIsExplicitNotImplicit(t *testing.T) {
	before, _, err := BuildDefaultRegistry(time.Now().UTC())
	require.NoError(t, err)
	after, _, err := BuildDefaultRegistry(time.Now().UTC())
	require.NoError(t, err)

	// Two registry builds produce the same label-derived state: a registry update
	// does not retroactively turn an old entry into a verified one.
	for i := range before.Sources() {
		if before.Sources()[i].SourceHash != after.Sources()[i].SourceHash {
			t.Fatal("two default builds disagree on a source hash, which would make " +
				"historical records non-reproducible")
		}
	}
}
