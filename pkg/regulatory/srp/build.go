// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.

package srp

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/vincents-ai/transparenz-server-oss/pkg/regulatory"
)

// Building a package, as opposed to assembling a map of strings.
//
// NewPackage computes a digest over whatever it is given. That is enough to tie
// a filing record to an artefact, but it proves nothing about the artefact: a
// digest over a non-conformant field set is an impeccable record of a document
// the platform would have rejected. Build closes that gap by validating against
// the reporting schema BEFORE the digest exists, so a package that cannot be
// filed cannot acquire one.
//
// Two things Build deliberately owns rather than trusting a caller with:
//
//   - The awareness timestamp. It is the anchor every Article 14 deadline is
//     computed from, and since v1.6 it is mandatory at early warning for both
//     event classes. If the caller could supply it independently of the report,
//     the product would tell a manufacturer one clock and file another. Build
//     takes the instant and derives the field, so the two cannot diverge.
//
//   - The authority's fields. Field 41 is written by the designated CSIRT.
//     Accepting a value for it would mean fabricating another party's record
//     inside an evidently-sealed package.

// BuildInput is everything a package is built from.
type BuildInput struct {
	// ReportID and OrgID identify the report the package belongs to.
	ReportID uuid.UUID
	OrgID    uuid.UUID

	// EventClass and Stage are validated against the schema; an unknown value
	// is an error rather than a default.
	EventClass regulatory.EventClass
	Stage      regulatory.Stage

	// CoordinatorID is the CSIRT designated as coordinator. Required: filing to
	// the wrong CSIRT loses the report.
	CoordinatorID string

	// Fields are the glossary field values, keyed by published position.
	Fields map[string]string

	// AwarenessAt is the instant the manufacturer became aware, as recorded on
	// the report. When set, Build derives the schema's awareness field from it.
	// When unset, the schema decides whether that is acceptable.
	AwarenessAt *time.Time

	// Facts are the report's own values for the fields it determines. They are
	// layered under Fields, and a disagreement between the two is an error: the
	// filing must not contradict the case file it reports.
	Facts *ReportFacts

	// Now is the generation instant. A zero value uses time.Now.
	Now time.Time
}

// ErrAuthorityAuthoredField is returned when a caller supplies a value for a
// field the receiving authority writes.
var ErrAuthorityAuthoredField = errors.New("srp: field is written by the receiving authority, not by the manufacturer")

// ErrAwarenessAnchorMissing is returned when a stage requires an awareness
// timestamp, the schema models one, and no instant was supplied.
//
// It is distinct from a generic conformance failure on purpose: "the report has
// no recorded awareness" is a different problem from "a field is blank", and it
// has a different remedy — the awareness fact and its evidence must be recorded,
// which is a legal determination, not a form entry.
var ErrAwarenessAnchorMissing = errors.New("srp: the schema requires an awareness timestamp and none was supplied")

// ErrSchemaCannotCarryAwareness is returned when an awareness instant was
// supplied but the schema has no field for it.
//
// Failing here rather than silently dropping the value is the point: a package
// built under such a schema would carry a complete-looking field set while the
// instant the deadlines run from went unrecorded.
var ErrSchemaCannotCarryAwareness = errors.New("srp: the reporting schema has no awareness field for this event class")

// Build validates the input against the schema and returns a digest-sealed
// package.
//
// A conformance failure is returned as a wrapped *regulatory.ConformanceError so
// a caller can enumerate the issues and show them to the filer; the package is
// never returned alongside an error.
func Build(schema *regulatory.ReportingSchema, in BuildInput) (Package, error) {
	if schema == nil {
		return Package{}, errors.New("srp: build requires the reporting schema to validate against")
	}
	if !in.Stage.Valid() {
		return Package{}, fmt.Errorf("srp: unknown stage %q", in.Stage)
	}
	if !in.EventClass.Valid() {
		return Package{}, fmt.Errorf("srp: unknown event class %q", in.EventClass)
	}

	fields := make(map[string]string, len(in.Fields)+1)
	for id, v := range in.Fields {
		fields[id] = v
	}

	// The authority's fields are never ours to write.
	for id := range fields {
		f, defined := schema.Field(id)
		if defined && f.AuthorityAuthored {
			return Package{}, fmt.Errorf("%w: field %s (%s)", ErrAuthorityAuthoredField, id, f.Name)
		}
	}

	if in.Facts != nil {
		if err := mergeDerived(fields, deriveFields(schema, in.Stage, in.EventClass, *in.Facts)); err != nil {
			return Package{}, err
		}
	}

	awarenessField, hasMapping := regulatory.AwarenessFieldFor(in.EventClass)
	if hasMapping {
		f, defined := schema.Field(awarenessField)
		applies := defined && f.RequirementAt(in.Stage, in.EventClass) != regulatory.RequirementNotApplicable
		switch {
		case in.AwarenessAt != nil && applies:
			fields[awarenessField] = regulatory.SRPTimestamp(*in.AwarenessAt)
		case in.AwarenessAt != nil && !defined:
			return Package{}, fmt.Errorf("%w: %s is not defined in %s",
				ErrSchemaCannotCarryAwareness, awarenessField, schema.ID)
		case in.AwarenessAt != nil && !applies:
			// The anchor is filed at the stage that asks for it. v1.6 marks it N/A
			// from the 72-hour notification onwards, and supplying it there is an
			// error the platform would raise — so it is dropped, not carried
			// forward. Dropping it silently is safe here only because the same
			// instant anchored the earlier stages that did file it, and this
			// package records nothing about it either way.
		}
	}

	if err := schema.Validate(in.Stage, in.EventClass, fields); err != nil {
		// Re-label the one issue that is not really a form problem.
		if hasMapping && in.AwarenessAt == nil {
			if f, ok := schema.Field(awarenessField); ok &&
				f.RequirementAt(in.Stage, in.EventClass) == regulatory.RequirementRequired {
				return Package{}, fmt.Errorf("%w: %s is %s and %s requires it at %s",
					ErrAwarenessAnchorMissing, awarenessField, "required", schema.ID, in.Stage)
			}
		}
		return Package{}, fmt.Errorf("srp: package does not conform to %s: %w", schema.ID, err)
	}

	now := in.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	return NewPackage(
		in.ReportID, in.OrgID,
		string(in.EventClass), string(in.Stage), schema.ID,
		in.CoordinatorID, fields, now,
	)
}
