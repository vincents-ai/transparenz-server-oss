// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.

// Package regulatory is a versioned registry of regulatory obligations,
// their provenance, and the schemas that describe what must be reported.
//
// # Why a registry rather than embedded logic
//
// ENISA states explicitly that its Single Reporting Platform guidance will
// change as the platform develops. A compliance engine that hard-codes the
// current field list therefore has exactly one safe behaviour when ENISA
// revises it: overwrite the old list, and lose the ability to explain why a
// report made six months ago looked the way it did.
//
// So nothing here is ever overwritten. Each source is pinned to a version, a
// publication date, a content hash and a supersession chain, and every control
// and reporting field is mapped against a *specific* source version. When
// ENISA publishes 1.4, the answer to "what did we owe in March?" is still
// answerable, because the 1.3 mapping is still there.
//
// # Law is not guidance
//
// Authority distinguishes what binds from what informs. The Commission's
// Article 14 reporting guidance is described as non-binding; ENISA's workflow
// documentation is operational guidance; only the Regulation itself is law.
// Presenting an ENISA workflow recommendation as though it were statutory text
// is a specific failure this package is built to prevent — see Authority.
package regulatory

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Authority classifies the legal weight of a regulatory source.
//
// The ordering matters: it is the order in which a reader should trust the
// source, and it is the reason a guidance document can never override a
// delegated act.
type Authority string

const (
	// AuthorityLaw is the Regulation itself.
	AuthorityLaw Authority = "LAW"

	// AuthorityDelegatedAct is a delegated act supplementing the Regulation.
	AuthorityDelegatedAct Authority = "DELEGATED_ACT"

	// AuthorityImplementingAct is an implementing act.
	AuthorityImplementingAct Authority = "IMPLEMENTING_ACT"

	// AuthorityCommissionGuidance is Commission guidance. Non-binding. The
	// Commission describes its CRA implementation guidance as such, and this
	// package will not let it be presented otherwise.
	AuthorityCommissionGuidance Authority = "COMMISSION_GUIDANCE"

	// AuthorityENISAOperationalGuidance is ENISA's operational guidance for
	// its Single Reporting Platform.
	AuthorityENISAOperationalGuidance Authority = "ENISA_OPERATIONAL_GUIDANCE"

	// AuthorityStandard is a standard (CEN/CENELEC/ISO).
	AuthorityStandard Authority = "STANDARD"

	// AuthorityNationalGuidance is guidance from a national authority.
	AuthorityNationalGuidance Authority = "NATIONAL_GUIDANCE"

	// AuthorityTransparenzInterpretation is our own reading of the above. It
	// is not a source of law and is always labelled as such, because an
	// implementation that quietly mixes its own interpretation into a legal
	// requirement is indistinguishable from one that is guessing.
	AuthorityTransparenzInterpretation Authority = "TRANSPARENZ_INTERPRETATION"
)

// Binding reports whether the authority creates legal obligations.
//
// Only the first three do. Everything else informs, advises or interprets.
func (a Authority) Binding() bool {
	switch a {
	case AuthorityLaw, AuthorityDelegatedAct, AuthorityImplementingAct:
		return true
	}
	return false
}

// Rank orders authorities from most to least authoritative. Used to detect a
// mapping that inverts the hierarchy.
func (a Authority) Rank() int {
	switch a {
	case AuthorityLaw:
		return 0
	case AuthorityDelegatedAct:
		return 1
	case AuthorityImplementingAct:
		return 2
	case AuthorityStandard:
		return 3
	case AuthorityCommissionGuidance:
		return 4
	case AuthorityENISAOperationalGuidance:
		return 5
	case AuthorityNationalGuidance:
		return 6
	case AuthorityTransparenzInterpretation:
		return 7
	}
	return 99
}

// Valid reports whether a is a known authority.
func (a Authority) Valid() bool { return a.Rank() < 99 }

// ErrUnknownAuthority is returned for an unrecognised authority class.
var ErrUnknownAuthority = errors.New("regulatory: unknown authority class")

// Source is a versioned, immutable reference to a regulatory document.
//
// Every field exists to answer one question asked months later: on what basis,
// as of when, and from which text did you conclude this? `SourceHash` in
// particular makes the answer checkable — a reviewer can re-hash the document
// and confirm the mapping was made against exactly the bytes we recorded.
type Source struct {
	// Authority is the legal weight of the document.
	Authority Authority `json:"authority"`

	// Document is the document identifier, e.g. "ENISA SRP Glossary".
	Document string `json:"document"`

	// Version is the document version, e.g. "1.3".
	Version string `json:"version"`

	// PublicationDate is when the version was published.
	PublicationDate time.Time `json:"publication_date"`

	// RetrievedAt is when Transparenz fetched it.
	RetrievedAt time.Time `json:"retrieved_at"`

	// EffectiveFrom is when the version's content became the operative
	// reference. Differs from PublicationDate when a document is published
	// ahead of taking effect.
	EffectiveFrom time.Time `json:"effective_from"`

	// Supersedes is the version this one replaces, if any. Forms a chain so
	// the history of a mapping is reconstructible.
	Supersedes string `json:"supersedes,omitempty"`

	// SourceHash is the SHA-256 of the retrieved document bytes, hex-encoded.
	SourceHash string `json:"source_hash"`

	// SourceURL is where the document was obtained.
	SourceURL string `json:"source_url,omitempty"`
}

// Key is the stable identity of a source version.
func (s Source) Key() string {
	return strings.Join([]string{string(s.Authority), s.Document, s.Version}, "|")
}

// Validate checks that a source is complete enough to be cited.
func (s Source) Validate() error {
	if !s.Authority.Valid() {
		return fmt.Errorf("%w: %q", ErrUnknownAuthority, s.Authority)
	}
	if strings.TrimSpace(s.Document) == "" {
		return errors.New("regulatory: source requires a document identifier")
	}
	if strings.TrimSpace(s.Version) == "" {
		return errors.New("regulatory: source requires a version")
	}
	if s.PublicationDate.IsZero() {
		return errors.New("regulatory: source requires a publication date")
	}
	if len(s.SourceHash) != sha256.Size*2 {
		return errors.New("regulatory: source requires a 64-character hex SHA-256 of the retrieved document")
	}
	if _, err := hex.DecodeString(s.SourceHash); err != nil {
		return fmt.Errorf("regulatory: source hash is not valid hex: %w", err)
	}
	return nil
}

// VerifyHash checks a document's bytes against the recorded hash.
func (s Source) VerifyHash(document []byte) bool {
	sum := sha256.Sum256(document)
	return hex.EncodeToString(sum[:]) == s.SourceHash
}

// ComputeSourceHash is the helper used when ingesting a document, so the
// recorded hash and the stored document cannot drift apart in format.
func ComputeSourceHash(document []byte) string {
	sum := sha256.Sum256(document)
	return hex.EncodeToString(sum[:])
}

// Registry holds versioned sources and the obligations mapped against them.
type Registry struct {
	sources     map[string]Source
	obligations map[string]Obligation
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{
		sources:     map[string]Source{},
		obligations: map[string]Obligation{},
	}
}

// AddSource registers a source version.
//
// A version is added, never replaced: registering the same key with different
// content is an error, because silently accepting it is how a mapping ends up
// citing a document version whose text nobody can reproduce.
func (r *Registry) AddSource(s Source) error {
	if err := s.Validate(); err != nil {
		return err
	}
	key := s.Key()
	if existing, ok := r.sources[key]; ok {
		if existing.SourceHash != s.SourceHash {
			return fmt.Errorf(
				"regulatory: source %s already registered with a different content hash; "+
					"versioned sources are immutable — add a new version instead", key)
		}
		return nil
	}
	r.sources[key] = s
	return nil
}

// Source returns a registered source by authority, document and version.
func (r *Registry) Source(authority Authority, document, version string) (Source, bool) {
	s, ok := r.sources[Source{Authority: authority, Document: document, Version: version}.Key()]
	return s, ok
}

// SourceByKey returns a registered source by its full key.
func (r *Registry) SourceByKey(key string) (Source, bool) {
	s, ok := r.sources[key]
	return s, ok
}

// CurrentSource returns the newest effective version of a document.
//
// "Newest" is by EffectiveFrom, not by registration order, so a document
// published ahead of its effective date does not become current prematurely.
func (r *Registry) CurrentSource(authority Authority, document string, at time.Time) (Source, bool) {
	var best Source
	found := false
	for _, s := range r.sources {
		if s.Authority != authority || s.Document != document {
			continue
		}
		if s.EffectiveFrom.After(at) {
			continue
		}
		if !found || s.EffectiveFrom.After(best.EffectiveFrom) {
			best, found = s, true
		}
	}
	return best, found
}

// SourceVersions lists every registered version of a document, oldest first.
func (r *Registry) SourceVersions(authority Authority, document string) []Source {
	var out []Source
	for _, s := range r.sources {
		if s.Authority == authority && s.Document == document {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].EffectiveFrom.Before(out[j].EffectiveFrom) })
	return out
}

// Sources returns every registered source, for export and audit.
func (r *Registry) Sources() []Source {
	out := make([]Source, 0, len(r.sources))
	for _, s := range r.sources {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out
}

// Obligation is a versioned regulatory requirement mapped to its sources.
type Obligation struct {
	// ID is the stable obligation identifier, e.g. "CRA-ART14-REPORT".
	ID string `json:"id"`

	// Title is a short human description.
	Title string `json:"title"`

	// Instrument is the legal instrument, e.g. "Regulation (EU) 2024/2847".
	Instrument string `json:"instrument"`

	// Article is the provision, e.g. "Article 14(2)".
	Article string `json:"article,omitempty"`

	// Authority is the class of the *binding* source for this obligation.
	Authority Authority `json:"authority"`

	// SourceKey pins the exact source version this obligation was read from.
	SourceKey string `json:"source_key"`

	// Guidance lists non-binding sources that informed the implementation.
	// Kept separate from SourceKey so a reader can never mistake guidance for
	// the legal basis.
	Guidance []string `json:"guidance,omitempty"`

	// Interpretation documents our own reading, where we go beyond the
	// sources. Always labelled.
	Interpretation string `json:"interpretation,omitempty"`

	// AppliesFrom is when the obligation binds.
	AppliesFrom time.Time `json:"applies_from"`

	// AppliesTo is the actor class the obligation binds (e.g. "manufacturer").
	AppliesTo string `json:"applies_to,omitempty"`
}

// AddObligation registers an obligation against a known source version.
func (r *Registry) AddObligation(o Obligation) error {
	if strings.TrimSpace(o.ID) == "" {
		return errors.New("regulatory: obligation requires an id")
	}
	if !o.Authority.Valid() {
		return fmt.Errorf("%w: %q", ErrUnknownAuthority, o.Authority)
	}
	src, ok := r.sources[o.SourceKey]
	if !ok {
		return fmt.Errorf("regulatory: obligation %s cites unregistered source %q", o.ID, o.SourceKey)
	}
	if src.Authority != o.Authority {
		return fmt.Errorf(
			"regulatory: obligation %s is classed %s but its source is %s; "+
				"guidance cannot be cited as the legal basis for an obligation",
			o.ID, o.Authority, src.Authority)
	}
	if !o.Authority.Binding() {
		return fmt.Errorf(
			"regulatory: obligation %s has non-binding authority %s; "+
				"non-binding sources belong in Guidance, not in the obligation's authority",
			o.ID, o.Authority)
	}
	for _, g := range o.Guidance {
		gs, ok := r.sources[g]
		if !ok {
			return fmt.Errorf("regulatory: obligation %s cites unregistered guidance %q", o.ID, g)
		}
		if gs.Authority.Binding() {
			return fmt.Errorf(
				"regulatory: obligation %s lists binding source %s as guidance; "+
					"it should be the obligation's source", o.ID, g)
		}
	}
	r.obligations[o.ID] = o
	return nil
}

// Obligation returns a registered obligation.
func (r *Registry) Obligation(id string) (Obligation, bool) {
	o, ok := r.obligations[id]
	return o, ok
}

// Obligations returns every registered obligation, sorted by id.
func (r *Registry) Obligations() []Obligation {
	out := make([]Obligation, 0, len(r.obligations))
	for _, o := range r.obligations {
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Validate walks the whole registry and reports every inconsistency.
//
// This is the function CI should run on every change to the registry. A
// guidance document quietly promoted to a legal basis, or an obligation citing
// a version nobody registered, is exactly the class of defect that is invisible
// in review and obvious in an audit.
func (r *Registry) Validate() error {
	var problems []string
	for key, s := range r.sources {
		if err := s.Validate(); err != nil {
			problems = append(problems, fmt.Sprintf("source %s: %v", key, err))
		}
		if s.Supersedes != "" {
			superseded := Source{Authority: s.Authority, Document: s.Document, Version: s.Supersedes}.Key()
			if _, ok := r.sources[superseded]; !ok {
				problems = append(problems, fmt.Sprintf(
					"source %s supersedes %s, which is not registered; the version chain is broken", key, superseded))
			}
		}
	}
	for id, o := range r.obligations {
		src, ok := r.sources[o.SourceKey]
		if !ok {
			problems = append(problems, fmt.Sprintf("obligation %s cites unregistered source %q", id, o.SourceKey))
			continue
		}
		if src.Authority != o.Authority {
			problems = append(problems, fmt.Sprintf(
				"obligation %s is classed %s but cites a %s source", id, o.Authority, src.Authority))
		}
		if !o.Authority.Binding() {
			problems = append(problems, fmt.Sprintf("obligation %s has non-binding authority %s", id, o.Authority))
		}
		for _, g := range o.Guidance {
			gs, ok := r.sources[g]
			if !ok {
				problems = append(problems, fmt.Sprintf("obligation %s cites unregistered guidance %q", id, g))
				continue
			}
			if gs.Authority.Binding() {
				problems = append(problems, fmt.Sprintf("obligation %s lists binding %s as guidance", id, g))
			}
			if gs.Authority.Rank() < src.Authority.Rank() {
				problems = append(problems, fmt.Sprintf(
					"obligation %s: guidance %s outranks its source %s", id, g, o.SourceKey))
			}
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("regulatory: registry validation failed:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return nil
}
