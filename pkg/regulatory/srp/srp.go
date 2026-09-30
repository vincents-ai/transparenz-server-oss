// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.

// Package srp is the submission transport boundary for the ENISA Single
// Reporting Platform.
//
// # Why this package exists as an interface and nothing more
//
// ENISA's initial Single Reporting Platform release provides no API.
// Organisations may automate their internal reporting workflow, but the
// notification itself is submitted through the SRP interface, by a person.
// ENISA states that API functionality may be considered at a later stage.
//
// It would therefore be a compliance misstatement — not just a premature
// feature — for Transparenz to claim it submits to ENISA programmatically.
// What it can honestly do is everything up to the wire: determine reportability,
// assemble and validate the package against the published glossary, and produce
// an auditable artefact for a human to file.
//
// # The shape
//
//	CRA Report -> SRP Schema Adapter -> Validated Submission Package -> Transport
//
// Everything left of Transport is implemented and tested. Transport is an
// interface with a single honest implementation today. When ENISA publishes an
// API, a second implementation is added and nothing in the reporting domain
// changes — which is the entire reason the boundary is drawn here rather than
// around the HTTP call.
package srp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"strings"
	"time"
)

// Via values recorded on a submission.
const (
	// ViaHumanSRP is the transport a submission actually takes today: a person
	// enters it in the SRP interface, and Transparenz records the fact and the
	// resulting case reference.
	ViaHumanSRP = "human_srp"

	// ViaExport is an offline package handed to whoever files it.
	ViaExport = "export"
)

// Transport delivers a validated submission package to a receiving authority.
//
// Implementations must be idempotent with respect to the package digest: a
// retried delivery of an unchanged package must not produce a second case at
// the authority, because two cases for one event is itself a reporting defect.
type Transport interface {
	// Name identifies the transport, and is recorded on the submission.
	Name() string

	// Delivers a package and returns the authority's acknowledgement.
	Deliver(ctx context.Context, p Package) (Receipt, error)
}

// ErrNoTransport is returned when a submission is attempted with no transport
// configured.
var ErrNoTransport = errors.New("srp: no transport configured; the package must be exported for manual filing")

// Package is a validated, ready-to-file submission for one stage of one report.
//
// The Digest is the SHA-256 of the exact bytes to be filed. It is what ties a
// recorded submission to an unalterable artefact: if the question "what exactly
// did you send?" is ever asked, this is the answer, and it can be re-derived
// from the package rather than trusted.
type Package struct {
	ReportID   uuid.UUID
	OrgID      uuid.UUID
	EventClass string
	Stage      string
	SchemaID   string

	// CoordinatorID is the CSIRT designated as coordinator the package is
	// addressed to.
	CoordinatorID string

	// Fields are the glossary field values, keyed by ENISA field identifier.
	Fields map[string]string

	// GeneratedAt is when the package was built.
	GeneratedAt time.Time

	// Digest is the SHA-256 over the canonical serialisation of the package.
	Digest string
}

// NewPackage builds a package and computes its digest.
//
// The digest covers the identifying fields and the field values, so changing
// any submitted value changes the digest. It deliberately does not cover
// GeneratedAt, which is transport metadata rather than content.
func NewPackage(reportID, orgID uuid.UUID, eventClass, stage, schemaID, coordinatorID string, fields map[string]string, now time.Time) (Package, error) {
	if reportID == uuid.Nil {
		return Package{}, errors.New("srp: package requires a report id")
	}
	if eventClass == "" {
		return Package{}, errors.New("srp: package requires an event class")
	}
	if stage == "" {
		return Package{}, errors.New("srp: package requires a stage")
	}
	if schemaID == "" {
		return Package{}, errors.New("srp: package requires the schema version it was validated against")
	}
	if coordinatorID == "" {
		return Package{}, errors.New("srp: package requires a coordinator; filing to the wrong CSIRT loses the report")
	}
	p := Package{
		ReportID:      reportID,
		OrgID:         orgID,
		EventClass:    eventClass,
		Stage:         stage,
		SchemaID:      schemaID,
		CoordinatorID: coordinatorID,
		Fields:        map[string]string{},
		GeneratedAt:   now,
	}
	for k, v := range fields {
		p.Fields[k] = v
	}
	p.Digest = p.computeDigest()
	return p, nil
}

// Digest encoding versions.
//
// The original encoding concatenated keys and values with tab and newline
// separators and no escaping. That is not merely fragile, it is ambiguous: a
// value containing a newline and a tab can manufacture a second field, so two
// structurally DIFFERENT packages produce identical bytes and therefore
// identical digests. Concretely, with identical report and organisation:
//
//	{"v5": "observed"} + {"v6": "high"}
//	{"v5": "observed\nfield=v6\thigh"}
//
// both serialise to the same field block and hash to the same value. This was
// reproduced before being fixed, and it means a package digest could not
// distinguish the document actually filed from a different one, which defeats
// the entire point of the digest: it is what ties a filing record to a specific
// document.
//
// The fix is a versioned, length-prefixed canonical encoding. A length prefix
// cannot be forged by content, so no value can impersonate a field boundary.
// Versioning exists so that digests already recorded against historical
// packages can still be verified: an old digest is not invalid evidence, it is
// evidence computed under a weaker encoding, and re-deriving it would rewrite
// history. The brief requires old evidence to remain interpretable and
// specifically forbids claiming a newly generated digest was the one originally
// filed.
const (
	// DigestPrefixV1 is the original, ambiguous encoding.
	DigestPrefixV1 = "sha256:"
	// DigestPrefixV2 is the current, length-prefixed canonical encoding.
	DigestPrefixV2 = "sha256-v2:"
)

// computeDigest produces a stable digest using the current canonical encoding.
//
// Field keys are sorted so two structurally identical packages always hash the
// same regardless of Go map iteration order. An unstable digest would make every
// retry look like a changed package and defeat deduplication entirely.
//
// Every element is length-prefixed, so no value can contain a sequence that
// looks like a field boundary and forge one.
func (p Package) computeDigest() string {
	keys := make([]string, 0, len(p.Fields))
	for k := range p.Fields {
		keys = append(keys, k)
	}
	sortStrings(keys)

	var b strings.Builder
	// Length-prefixed, with a distinct label for the identity block so a field
	// key can never be mistaken for one of the identity elements.
	b.WriteString("srp-package-v2\x00")
	writeLP(&b, "report_id", p.ReportID.String())
	writeLP(&b, "org_id", p.OrgID.String())
	writeLP(&b, "event_class", p.EventClass)
	writeLP(&b, "stage", p.Stage)
	writeLP(&b, "schema_id", p.SchemaID)
	writeLP(&b, "coordinator_id", p.CoordinatorID)
	writeLP(&b, "field_count", fmt.Sprintf("%d", len(keys)))
	for _, k := range keys {
		writeLP(&b, "field", k)
		writeLP(&b, "value", p.Fields[k])
	}
	sum := sha256.Sum256([]byte(b.String()))
	return DigestPrefixV2 + hex.EncodeToString(sum[:])
}

// writeLP writes one length-prefixed element: the label, the byte length of the
// value, and the value itself. The length is the reason the encoding is
// unambiguous — a reader never has to search for a delimiter, so no value can
// contain one.
func writeLP(b *strings.Builder, label, value string) {
	fmt.Fprintf(b, "%d:%s=%d:%s;", len(label), label, len(value), value)
}

// computeDigestLegacy reproduces the original v1 encoding exactly.
//
// It exists solely so VerifyDigest can still accept a digest recorded against a
// historical package. It must never be used to GENERATE a digest, because a
// newly minted legacy digest would inherit the ambiguity, and a digest computed
// now must not be presented as one that was computed then.
func (p Package) computeDigestLegacy() string {
	keys := make([]string, 0, len(p.Fields))
	for k := range p.Fields {
		keys = append(keys, k)
	}
	sortStrings(keys)

	var b strings.Builder
	fmt.Fprintf(&b, "report=%s\norg=%s\nclass=%s\nstage=%s\nschema=%s\ncoordinator=%s\n",
		p.ReportID, p.OrgID, p.EventClass, p.Stage, p.SchemaID, p.CoordinatorID)
	for _, k := range keys {
		fmt.Fprintf(&b, "field=%s\t%s\n", k, p.Fields[k])
	}
	sum := sha256.Sum256([]byte(b.String()))
	return DigestPrefixV1 + hex.EncodeToString(sum[:])
}

// VerifyDigest reports whether the recorded digest matches this package.
//
// It accepts either encoding. Rejecting a legacy digest would invalidate
// evidence that was genuinely recorded at the time, and re-deriving a v2 digest
// to "match" it would claim the historical digest was something it was not.
// Where a package matches only under the legacy encoding, the caller is
// verifying weaker evidence and should say so rather than treat the two as
// equivalent.
func (p Package) VerifyDigest() bool {
	recorded := p.Digest
	switch {
	case strings.HasPrefix(recorded, DigestPrefixV2):
		return p.computeDigest() == recorded
	case strings.HasPrefix(recorded, DigestPrefixV1):
		return p.computeDigestLegacy() == recorded
	default:
		return false
	}
}

// VerifiedUnderLegacyEncoding reports whether the package matches only a
// digest recorded under the original, ambiguous encoding. Such a digest cannot
// distinguish two different documents, so anything relying on it is evidence of
// a weaker kind and should be presented as such.
func (p Package) VerifiedUnderLegacyEncoding() bool {
	return p.Digest != "" && p.computeDigest() != p.Digest && p.computeDigestLegacy() == p.Digest
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// Receipt is an authority's acknowledgement of a delivered package.
type Receipt struct {
	// CaseReference is the identifier the authority assigned. Empty for a
	// package that has been exported but not yet filed.
	CaseReference string `json:"case_reference,omitempty"`

	// ReceivedAt is when the authority acknowledged it.
	ReceivedAt time.Time `json:"received_at,omitempty"`

	// Digest is the package digest the authority acknowledged. Recording it
	// lets a later question "which exact package was filed?" be answered.
	Digest string `json:"digest,omitempty"`

	// Pending records that the package is prepared but not yet filed by a
	// person. It is a receipt for the preparation, not for a submission.
	Pending bool `json:"pending,omitempty"`
}

// ManualTransport is the only honest transport available today: it produces the
// package and hands it to a person.
//
// It does not pretend to have filed anything. The returned Receipt has
// Pending=true and an empty case reference, and the caller records the
// submission only when a human has actually entered it in the SRP interface and
// the resulting case reference is supplied.
//
// This is the adapter that gets replaced when ENISA publishes an API. Nothing
// in the reporting domain references it directly.
type ManualTransport struct {
	// Exporter renders the package for human filing. Required.
	Exporter Exporter
}

// Name implements Transport.
func (m *ManualTransport) Name() string { return ViaHumanSRP }

// Deliver implements Transport. It hands the package to the exporter and
// reports it as pending.
func (m *ManualTransport) Deliver(ctx context.Context, p Package) (Receipt, error) {
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}
	if !p.VerifyDigest() {
		return Receipt{}, errors.New("srp: package content does not match its digest; refusing to hand over altered content")
	}
	if m.Exporter == nil {
		return Receipt{}, errors.New("srp: manual transport requires an exporter")
	}
	if err := m.Exporter.Export(ctx, p); err != nil {
		return Receipt{}, err
	}
	return Receipt{
		Digest:     p.Digest,
		ReceivedAt: time.Now().UTC(),
		Pending:    true,
	}, nil
}

// Exporter renders a package into an artefact a person can file.
type Exporter interface {
	Export(ctx context.Context, p Package) error
}
