// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.

package regulatory

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// identifierPattern matches the identifier forms ENISA's reporting fields use
// in practice: CVE-2026-31337, EUVD-2026-1234, SRP-2026-000123, and bare
// alphanumeric tokens. Anchored and case-insensitive on the prefix.
var identifierPattern = regexp.MustCompile(`^(?i)(CVE|EUVD|SRP)-?[0-9]{4}-?[0-9]+$|^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// EventClass is a reportable event class a field can apply to.
type EventClass string

const (
	// EventClassAEV is an actively exploited vulnerability report.
	EventClassAEV EventClass = "AEV"

	// EventClassSI is a severe incident report.
	EventClassSI EventClass = "SI"
)

// Valid reports whether c is a known event class.
func (c EventClass) Valid() bool { return c == EventClassAEV || c == EventClassSI }

// Requirement is how strongly a field is expected at a given stage.
type Requirement string

const (
	// RequirementRequired — the field must be present. Its absence makes the
	// submission package invalid.
	RequirementRequired Requirement = "required"

	// RequirementInheritedOrUpdate — ENISA expects the field to be carried
	// forward from the previous submission, optionally updated. Omitting it
	// without updating is a defect, but it is not the same as omitting a
	// required field: the previous submission's value stands.
	RequirementInheritedOrUpdate Requirement = "inherited_or_update"

	// RequirementOptional — expected where the facts support it.
	RequirementOptional Requirement = "optional"

	// RequirementNotApplicable — the field does not apply at this stage for
	// this event class.
	RequirementNotApplicable Requirement = "not_applicable"
)

// FieldFormat describes the expected representation of a field's value.
type FieldFormat string

const (
	FormatText       FieldFormat = "text"
	FormatMultiline  FieldFormat = "multiline_text"
	FormatDate       FieldFormat = "date"
	FormatDateTime   FieldFormat = "date_time"
	FormatEnum       FieldFormat = "enum"
	FormatBoolean    FieldFormat = "boolean"
	FormatIdentifier FieldFormat = "identifier"
	FormatURI        FieldFormat = "uri"
	FormatInteger    FieldFormat = "integer"
	FormatList       FieldFormat = "list"
)

// StageRequirement is a field's requirement at one stage for one event class.
type StageRequirement struct {
	Stage       Stage       `json:"stage"`
	EventClass  EventClass  `json:"event_class"`
	Requirement Requirement `json:"requirement"`
}

// Stage is a reporting stage in a reporting schema.
type Stage string

const (
	StageEarlyWarning    Stage = "early_warning"
	StageNotification72h Stage = "notification_72h"
	StageFinalReport     Stage = "final_report"
)

// SchemaStages is the canonical stage order, which is also the order the SRP
// workflow proceeds in.
var SchemaStages = []Stage{StageEarlyWarning, StageNotification72h, StageFinalReport}

// Valid reports whether s is a known stage.
func (s Stage) Valid() bool {
	switch s {
	case StageEarlyWarning, StageNotification72h, StageFinalReport:
		return true
	}
	return false
}

// ReportingField is one field in a reporting schema, with its applicability and
// per-stage requirement.
//
// This is the machine-readable form of what ENISA's SRP Glossary specifies
// field by field. Keeping it as data rather than as Go conditionals is what
// makes the report schema-driven: when ENISA revises the glossary, a new
// version of this structure is registered and the engine adapts, rather than
// somebody editing conditionals and hoping they found them all.
type ReportingField struct {
	// ID is the glossary's own field identifier (e.g. "v25"). Using ENISA's
	// identifiers rather than our own means a submission package can be
	// checked against the published glossary by someone else.
	ID string `json:"id"`

	// Name is the field name.
	Name string `json:"name"`

	// Description is the field's meaning.
	Description string `json:"description,omitempty"`

	// Format is the expected representation.
	Format FieldFormat `json:"format"`

	// EnumValues constrains FormatEnum fields.
	EnumValues []string `json:"enum_values,omitempty"`

	// ApplicableTo is the event classes the field applies to. A field that
	// applies to neither is a schema error.
	ApplicableTo []EventClass `json:"applies_to"`

	// Stages is the per-stage, per-event-class requirement.
	Stages []StageRequirement `json:"stages"`

	// SourceKey pins the glossary version this field definition was read from.
	SourceKey string `json:"source_key"`
}

// AppliesTo reports whether the field is in scope for an event class.
func (f ReportingField) AppliesTo(class EventClass) bool {
	for _, c := range f.ApplicableTo {
		if c == class {
			return true
		}
	}
	return false
}

// RequirementAt returns the field's requirement for a stage and event class.
//
// An unstated combination is not "optional" — it is not applicable, because
// the glossary specifies applicability explicitly. Defaulting an omission to
// optional would silently drop required data.
func (f ReportingField) RequirementAt(stage Stage, class EventClass) Requirement {
	for _, sr := range f.Stages {
		if sr.Stage == stage && sr.EventClass == class {
			return sr.Requirement
		}
	}
	if !f.AppliesTo(class) {
		return RequirementNotApplicable
	}
	return RequirementNotApplicable
}

// ReportingSchema is a versioned field model for one reporting regime.
type ReportingSchema struct {
	// ID identifies the schema, e.g. "ENISA-SRP-1.3".
	ID string `json:"id"`

	// Regime is the regulatory regime, e.g. "CRA-ARTICLE-14".
	Regime string `json:"regime"`

	// SourceKey pins the glossary version this schema was transcribed from.
	SourceKey string `json:"source_key"`

	// PublishedAt is the version's publication date.
	PublishedAt time.Time `json:"published_at"`

	fields map[string]ReportingField
	order  []string
}

// ErrNoSchema is returned when no schema is registered for a regime.
var ErrNoSchema = errors.New("regulatory: no reporting schema registered for the regime")

// Field returns a field by its glossary identifier.
func (s *ReportingSchema) Field(id string) (ReportingField, bool) {
	f, ok := s.fields[id]
	return f, ok
}

// Fields returns every field in stable identifier order.
func (s *ReportingSchema) Fields() []ReportingField {
	out := make([]ReportingField, 0, len(s.order))
	for _, id := range s.order {
		out = append(out, s.fields[id])
	}
	return out
}

// AddField registers a field. Re-adding an identical field is a no-op;
// re-adding a *different* field under the same identifier is rejected, because
// a versioned schema is immutable for the same reason sources are.
func (s *ReportingSchema) AddField(f ReportingField) error {
	if strings.TrimSpace(f.ID) == "" {
		return errors.New("regulatory: reporting field requires an id")
	}
	if strings.TrimSpace(f.Name) == "" {
		return errors.New("regulatory: reporting field requires a name")
	}
	if f.Format == "" {
		return errors.New("regulatory: reporting field requires a format")
	}
	if len(f.ApplicableTo) == 0 {
		return fmt.Errorf("regulatory: field %s applies to no event class", f.ID)
	}
	for _, c := range f.ApplicableTo {
		if !c.Valid() {
			return fmt.Errorf("regulatory: field %s has unknown event class %q", f.ID, c)
		}
	}
	if f.Format == FormatEnum && len(f.EnumValues) == 0 {
		return fmt.Errorf("regulatory: enum field %s declares no values", f.ID)
	}
	if f.SourceKey == "" {
		return fmt.Errorf("regulatory: field %s is not pinned to a source version", f.ID)
	}
	for _, sr := range f.Stages {
		if !sr.Stage.Valid() {
			return fmt.Errorf("regulatory: field %s references unknown stage %q", f.ID, sr.Stage)
		}
		if !sr.EventClass.Valid() {
			return fmt.Errorf("regulatory: field %s references unknown event class %q", f.ID, sr.EventClass)
		}
		if !f.AppliesTo(sr.EventClass) {
			return fmt.Errorf("regulatory: field %s declares a requirement for %s but does not apply to it", f.ID, sr.EventClass)
		}
	}
	if existing, ok := s.fields[f.ID]; ok {
		if !fieldsEqual(existing, f) {
			return fmt.Errorf(
				"regulatory: field %s already defined differently in schema %s; "+
					"schemas are immutable — register a new schema version", f.ID, s.ID)
		}
		return nil
	}
	s.fields[f.ID] = f
	s.order = append(s.order, f.ID)
	sort.Strings(s.order)
	return nil
}

func fieldsEqual(a, b ReportingField) bool {
	ra, rb := fmt.Sprintf("%v", a.Stages), fmt.Sprintf("%v", b.Stages)
	if a.Name != b.Name || a.Description != b.Description || a.Format != b.Format ||
		a.SourceKey != b.SourceKey || ra != rb ||
		fmt.Sprintf("%v", a.ApplicableTo) != fmt.Sprintf("%v", b.ApplicableTo) ||
		fmt.Sprintf("%v", a.EnumValues) != fmt.Sprintf("%v", b.EnumValues) {
		return false
	}
	return true
}

// RequiredFields returns the fields required for a stage and event class.
func (s *ReportingSchema) RequiredFields(stage Stage, class EventClass) []ReportingField {
	var out []ReportingField
	for _, f := range s.Fields() {
		if f.RequirementAt(stage, class) == RequirementRequired {
			out = append(out, f)
		}
	}
	return out
}

// ValidationIssue is one conformance failure.
type ValidationIssue struct {
	FieldID string     `json:"field_id"`
	Stage   Stage      `json:"stage"`
	Class   EventClass `json:"event_class"`
	Problem string     `json:"problem"`
}

// ConformanceError is the typed form of a validation failure, so a caller can
// report every missing field at once rather than one per round trip.
type ConformanceError struct{ issues []ValidationIssue }

func (e *ConformanceError) Error() string {
	parts := make([]string, 0, len(e.issues))
	for _, i := range e.issues {
		parts = append(parts, fmt.Sprintf("%s/%s/%s: %s", i.Stage, i.Class, i.FieldID, i.Problem))
	}
	return "regulatory: submission package does not conform: " + strings.Join(parts, "; ")
}

// Issues returns the individual validation failures.
func (e *ConformanceError) Issues() []ValidationIssue { return e.issues }

// Values is a submission package's field values keyed by glossary field id.
type Values map[string]string

// Validate checks a package against the schema for a stage and event class.
//
// It reports every problem it finds rather than stopping at the first, because
// a filer working against a 24-hour deadline is better served by the full list.
func (s *ReportingSchema) Validate(stage Stage, class EventClass, values Values) error {
	if !stage.Valid() {
		return fmt.Errorf("regulatory: unknown stage %q", stage)
	}
	if !class.Valid() {
		return fmt.Errorf("regulatory: unknown event class %q", class)
	}
	var issues []ValidationIssue
	for _, f := range s.Fields() {
		req := f.RequirementAt(stage, class)
		v, present := values[f.ID]
		if strings.TrimSpace(v) == "" {
			present = false
		}
		switch req {
		case RequirementNotApplicable:
			// A value supplied for a field that does not apply is worth
			// reporting: it usually means the wrong event class was selected.
			if present {
				issues = append(issues, ValidationIssue{
					FieldID: f.ID, Stage: stage, Class: class,
					Problem: fmt.Sprintf("field does not apply to %s at %s but a value was supplied", class, stage),
				})
			}
		case RequirementRequired:
			if !present {
				issues = append(issues, ValidationIssue{
					FieldID: f.ID, Stage: stage, Class: class,
					Problem: "required by " + s.ID + " but absent",
				})
			}
		}
		if present {
			if issue := checkFormat(f, v); issue != "" {
				issues = append(issues, ValidationIssue{FieldID: f.ID, Stage: stage, Class: class, Problem: issue})
			}
		}
	}
	// Values for fields the schema does not define at all are reported too:
	// an unrecognised key usually means the package was built against a
	// glossary version we are no longer validating against.
	known := map[string]bool{}
	for _, f := range s.Fields() {
		known[f.ID] = true
	}
	var extra []string
	for id := range values {
		if !known[id] {
			extra = append(extra, id)
		}
	}
	sort.Strings(extra)
	for _, id := range extra {
		issues = append(issues, ValidationIssue{
			FieldID: id, Stage: stage, Class: class,
			Problem: "field is not defined in " + s.ID,
		})
	}
	if len(issues) > 0 {
		sort.Slice(issues, func(i, j int) bool { return issues[i].FieldID < issues[j].FieldID })
		return &ConformanceError{issues: issues}
	}
	return nil
}

func checkFormat(f ReportingField, v string) string {
	switch f.Format {
	case FormatEnum:
		for _, allowed := range f.EnumValues {
			if v == allowed {
				return ""
			}
		}
		return fmt.Sprintf("value %q is not one of [%s]", v, strings.Join(f.EnumValues, ", "))
	case FormatDate, FormatDateTime:
		for _, layout := range []string{time.RFC3339, "2006-01-02"} {
			if _, err := time.Parse(layout, v); err == nil {
				return ""
			}
		}
		return fmt.Sprintf("value %q is not a valid date or date-time", v)
	case FormatURI:
		if !strings.Contains(v, "://") {
			return fmt.Sprintf("value %q is not a URI", v)
		}
		return ""
	case FormatIdentifier:
		if !identifierPattern.MatchString(v) {
			return fmt.Sprintf("value %q is not a well-formed identifier", v)
		}
		return ""
	default:
		return ""
	}
}

// SchemaRegistry holds reporting schemas by id.
type SchemaRegistry struct {
	schemas  map[string]*ReportingSchema
	byRegime map[string]string // regime -> current schema id
}

// NewSchemaRegistry returns an empty schema registry.
func NewSchemaRegistry() *SchemaRegistry {
	return &SchemaRegistry{schemas: map[string]*ReportingSchema{}, byRegime: map[string]string{}}
}

// Register adds a schema and marks it current for its regime.
//
// Registering a *newer* version does not remove the older one: a package
// validated last March is still validated against the schema that was current
// in March.
func (sr *SchemaRegistry) Register(s *ReportingSchema) error {
	if s == nil || s.ID == "" {
		return errors.New("regulatory: schema requires an id")
	}
	if s.SourceKey == "" {
		return fmt.Errorf("regulatory: schema %s is not pinned to a source version", s.ID)
	}
	if s.PublishedAt.IsZero() {
		return fmt.Errorf("regulatory: schema %s requires a publication date", s.ID)
	}
	if s.fields == nil {
		s.fields = map[string]ReportingField{}
	}
	if _, exists := sr.schemas[s.ID]; exists {
		return fmt.Errorf("regulatory: schema %s already registered; schemas are immutable", s.ID)
	}
	sr.schemas[s.ID] = s
	if current, ok := sr.byRegime[s.Regime]; ok {
		if existing := sr.schemas[current]; existing != nil && existing.PublishedAt.After(s.PublishedAt) {
			return nil // an older version does not become current
		}
	}
	sr.byRegime[s.Regime] = s.ID
	return nil
}

// Schema returns a schema by id.
func (sr *SchemaRegistry) Schema(id string) (*ReportingSchema, bool) {
	s, ok := sr.schemas[id]
	return s, ok
}

// Current returns the current schema for a regime.
func (sr *SchemaRegistry) Current(regime string) (*ReportingSchema, error) {
	id, ok := sr.byRegime[regime]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNoSchema, regime)
	}
	return sr.schemas[id], nil
}

// SchemaAt returns the schema that was current for a regime at an instant.
func (sr *SchemaRegistry) SchemaAt(regime string, at time.Time) (*ReportingSchema, error) {
	var best *ReportingSchema
	for _, s := range sr.schemas {
		if s.Regime != regime || s.PublishedAt.After(at) {
			continue
		}
		if best == nil || s.PublishedAt.After(best.PublishedAt) {
			best = s
		}
	}
	if best == nil {
		return nil, fmt.Errorf("%w: %s as of %s", ErrNoSchema, regime, at.Format(time.RFC3339))
	}
	return best, nil
}
