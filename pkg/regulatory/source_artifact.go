package regulatory

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Source provenance.
//
// The registry previously computed SourceHash from a LABEL rather than from
// the document, e.g. ComputeSourceHash([]byte("CRA-ART14-GUIDANCE|C(2026) 5252")),
// and supplied a single RetrievedAt at construction time for every entry.
//
// That is not a weak hash; it is not a hash of the source at all. Two different
// texts published under the same title and version produce an identical
// "source hash", so the value cannot answer the only question an auditor asks of
// it: which text was actually reviewed when this obligation was mapped. It also
// means a document that changes while keeping its version number is
// undetectable, which is precisely the case where a compliance decision would
// silently become wrong.
//
// The remediation here is to make the distinction machine-readable rather than
// to fabricate bytes we do not have. Transparency does not ship the ENISA
// glossary or the CRA text, so inventing a document body to hash would be
// exactly the class of defect ADR-002 exists to prevent: a confident, verifiable
// -looking claim resting on nothing.
//
// Instead:
//
//   - SourceArtifact retains the ACTUAL retrieved bytes, their URL, the real
//     retrieval instant and the content hash computed from those bytes. An
//     auditor can re-hash it and confirm the mapping was made against exactly
//     the text recorded.
//   - Source.ArtifactDerived says which of the two a given entry is. A label hash
//     is retained so historical records stay interpretable, but it is marked, and
//     anything that must not rely on unverified provenance can filter on it.

// ArtifactDerived values for Source.ArtifactDerived.
const (
	// ArtifactRetained means SourceHash was computed from retained source bytes,
	// and an auditor can retrieve them and reproduce the hash.
	ArtifactRetained = "retained"

	// ArtifactLabelDerived means SourceHash was computed from a LABEL, not from
	// the document. It identifies a title and version and nothing more. This is
	// what the built-in registry entries currently are, and marking them is
	// honest in a way the previous code was not.
	ArtifactLabelDerived = "label_derived"
)

// SourceArtifact is the retained evidence for a regulatory source.
type SourceArtifact struct {
	// Document identifies what was retrieved.
	Document string `json:"document"`
	Version  string `json:"version"`

	// CanonicalURL is where the document was obtained from.
	CanonicalURL string `json:"canonical_url"`

	// RetrievedAt is the real instant this particular copy was fetched. It is
	// per-artifact, not per-registry, because two documents were not fetched at
	// the same moment.
	RetrievedAt time.Time `json:"retrieved_at"`

	// ContentHash is SHA-256 over Content, and nothing else. It is deliberately
	// separate from any hash over a normalised extraction: two normalisations of
	// the same document may differ, and an auditor re-hashing the retained bytes
	// must get the same answer the registry holds.
	ContentHash string `json:"content_hash"`

	// Content is the retained document text. Holding it is what makes the hash
	// checkable rather than decorative.
	Content []byte `json:"-"`

	// Reviewer records who read the document, which is a different claim from
	// when it was fetched.
	Reviewer string `json:"reviewer,omitempty"`
}

// NewSourceArtifact builds an artifact from retained bytes, computing the content
// hash from those bytes rather than from a label.
func NewSourceArtifact(document, version, canonicalURL string, retrievedAt time.Time, content []byte, reviewer string) SourceArtifact {
	sum := sha256.Sum256(content)
	return SourceArtifact{
		Document:     document,
		Version:      version,
		CanonicalURL: canonicalURL,
		RetrievedAt:  retrievedAt,
		ContentHash:  "sha256:" + hex.EncodeToString(sum[:]),
		Content:      content,
		Reviewer:     reviewer,
	}
}

// Verify recomputes the content hash and reports whether the retained bytes
// still match what the registry claims. It is what an auditor runs.
func (a SourceArtifact) Verify() bool {
	if a.ContentHash == "" || len(a.Content) == 0 {
		return false
	}
	sum := sha256.Sum256(a.Content)
	return a.ContentHash == "sha256:"+hex.EncodeToString(sum[:])
}

// LabelHash is the legacy, label-derived value used for built-in registry
// entries. It is retained so existing records remain interpretable, and is always
// paired with ArtifactDerived = ArtifactLabelDerived.
func LabelHash(document, version string) string {
	return "label:" + ComputeSourceHash([]byte(document+"|"+version))
}

// AttachArtifact records a retained artifact against a source and replaces the
// label-derived hash with the content hash.
//
// Replacing rather than adding is deliberate: keeping a label hash as the
// primary SourceHash would leave the field meaning the weaker of the two things,
// and the whole point of the change is that SourceHash is the content hash when
// an artifact is available.
func (s *Source) AttachArtifact(a SourceArtifact) {
	if a.ContentHash == "" {
		return
	}
	s.ArtifactDerived = ArtifactRetained
	s.SourceHash = a.ContentHash
	s.SourceURL = a.CanonicalURL
	s.RetrievedAt = a.RetrievedAt
	if a.Reviewer != "" {
		s.Reviewer = a.Reviewer
	}
	if a.Document != "" {
		s.Document = a.Document
	}
	if a.Version != "" {
		s.Version = a.Version
	}
}

// IsVerifiable reports whether this source's hash can be reproduced from
// retained bytes. Anything that must not rely on unverified provenance — an
// automated compliance determination, an assertion in a customer-facing
// document — should require this to be true.
func (s Source) IsVerifiable() bool {
	return s.ArtifactDerived == ArtifactRetained && strings.HasPrefix(s.SourceHash, "sha256:")
}

// Describe renders the provenance in human terms, so a reviewer reading a report
// can see whether the source behind an obligation was actually retained.
func (s Source) Describe() string {
	switch s.ArtifactDerived {
	case ArtifactRetained:
		return fmt.Sprintf("%s %s — content hash %s from %s, retrieved %s",
			s.Document, s.Version, s.SourceHash, s.SourceURL, s.RetrievedAt.Format(time.RFC3339))
	default:
		return fmt.Sprintf("%s %s — NOT VERIFIABLE: the recorded hash is derived from the "+
			"document label, not from retained text, so it does not evidence which "+
			"wording was reviewed", s.Document, s.Version)
	}
}
