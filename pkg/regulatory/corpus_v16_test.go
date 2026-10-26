// SPDX-FileCopyrightText: 2026 Vincent Palmer
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Transparenz, an open-source CRA compliance server.
// It is licensed under the GNU Affero General Public License v3.0; see LICENSE.

package regulatory

import (
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vincents-ai/transparenz-server-oss/pkg/regulatory/cra"
)

// v16Schema returns the current schema, asserting it is the v1.6 transcription
// so a future version cannot silently retarget these tests.
func v16Schema(t *testing.T) *ReportingSchema {
	t.Helper()
	_, sr := corpus(t)
	s, ok := sr.Schema(SchemaIDSRPGlossaryV16)
	require.True(t, ok, "the v1.6 schema must be registered")
	require.Equal(t, SchemaIDSRPGlossaryV16, s.ID)
	return s
}

// requiredIDs returns the identifiers required at one stage and class, sorted so
// comparisons are order-independent.
func requiredIDs(s *ReportingSchema, stage Stage, class EventClass) []string {
	out := []string{}
	for _, f := range s.RequiredFields(stage, class) {
		out = append(out, f.ID)
	}
	sort.Strings(out)
	return out
}

// The requiredness matrix is the substance of the v1.6 change, so it is asserted
// directly against the published table rather than only through fixtures. A
// fixture proves that a complete package validates; this proves that an
// INCOMPLETE one does not, per stage and per event class.
//
// Expected sets read from the glossary; "Required" and "Mandatory" both appear
// there and both mean the value must be present.
func TestV16RequiredSetsMatchThePublishedMatrix(t *testing.T) {
	s := v16Schema(t)

	commonEW := []string{
		FieldV16NotificationType, FieldV16Title, FieldV16Summary,
		FieldV16ManufacturerName, FieldV16MemberStates,
		FieldV16ProductName, FieldV16ProductVersion,
	}

	cases := []struct {
		name     string
		stage    Stage
		class    EventClass
		expected []string
	}{
		{
			// Common fields plus the AEV awareness timestamp, which v1.6 makes
			// mandatory and v1.4 only footnoted as forthcoming.
			name: "AEV / early warning", stage: StageEarlyWarning, class: EventClassAEV,
			expected: append(append([]string{}, commonEW...), FieldV16AEVAwareness),
		},
		{
			// The 72-hour AEV notification requires the general information and
			// nothing else: severity, impact and the measure dates are optional
			// here and required at the final report.
			name: "AEV / 72h", stage: StageNotification72h, class: EventClassAEV,
			expected: []string{FieldV16GeneralInfo},
		},
		{
			name: "AEV / final report", stage: StageFinalReport, class: EventClassAEV,
			expected: []string{
				FieldV16MeasuresTaken, FieldV16MeasuresForUsers,
				FieldV16MeasureDate, FieldV16UpdateDetails,
				FieldV16SeverityDesc, FieldV16ImpactDesc,
			},
		},
		{
			// i31 is required at early warning and is the field most easily lost:
			// it has no counterpart in the earlier schemas at all.
			name: "SI / early warning", stage: StageEarlyWarning, class: EventClassSI,
			expected: append(append([]string{}, commonEW...), FieldV16IncidentSuspected, FieldV16IncidentAwareness),
		},
		{
			name: "SI / 72h", stage: StageNotification72h, class: EventClassSI,
			expected: []string{FieldV16IncidentNature, FieldV16IncidentAssessment},
		},
		{
			name: "SI / final report", stage: StageFinalReport, class: EventClassSI,
			expected: []string{
				FieldV16MeasuresTaken, FieldV16MeasuresForUsers,
				FieldV16IncidentMeasures, FieldV16IncidentSeverity,
				FieldV16IncidentImpact, FieldV16IncidentRootCause,
			},
		},
	}

	require.Len(t, cases, 6, "the matrix is 2 event classes x 3 stages")

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expected := append([]string{}, tc.expected...)
			sort.Strings(expected)
			assert.Equal(t, expected, requiredIDs(s, tc.stage, tc.class))
		})
	}
}

// Every field in the v1.6 schema carries a transcribed identifier. This is the
// guard the V2 builder deferred to a function that did not exist; here it is an
// assertion that fails if any field's position was assigned locally.
func TestEveryV16FieldIdentifierIsSourced(t *testing.T) {
	s := v16Schema(t)
	fields := s.Fields()
	require.NotEmpty(t, fields)

	for _, f := range fields {
		assert.True(t, f.IdentifierSourced,
			"field %s (%s) is marked as a locally-assigned identifier, not a transcribed one", f.ID, f.Name)
		assert.Equal(t, f.ID, f.IdentifierPosition,
			"field %s must carry its own published position, got %q", f.ID, f.IdentifierPosition)
		require.NotEmpty(t, f.SourceKey, "field %s is not pinned to a source version", f.ID)
		require.NotEmpty(t, f.Format, "field %s has no format", f.ID)
	}
}

// The glossary states a character limit for most fields, and the SRP form
// enforces it. A value this product accepts but the platform rejects is a filing
// that fails at the last moment, in front of a deadline.
func TestV16CharacterLimitsAreEnforced(t *testing.T) {
	s := v16Schema(t)

	f, ok := s.Field(FieldV16Title)
	require.True(t, ok)
	require.Equal(t, 255, f.MaxLength)

	values := Values{FieldV16Title: strings.Repeat("x", 256)}
	err := s.Validate(StageEarlyWarning, EventClassAEV, values)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at most 255")

	// The limit counts characters, not bytes: a 255-character title of non-ASCII
	// text is 510 bytes long, and must be accepted. Asserted as a clean
	// validation of a complete early warning, not as the absence of one issue —
	// a check that only inspects the issues of a nil error passes whatever the
	// limit does.
	complete := Values{}
	for k, v := range values {
		complete[k] = v
	}
	for _, id := range requiredIDs(s, StageEarlyWarning, EventClassAEV) {
		if _, ok := complete[id]; !ok {
			complete[id] = "placeholder"
		}
	}
	complete[FieldV16NotificationType] = "Vulnerability"
	complete[FieldV16AEVAwareness] = "2026-09-20 08:45 UTC"
	complete[FieldV16Title] = strings.Repeat("ä", 255)
	require.NoError(t, s.Validate(StageEarlyWarning, EventClassAEV, complete),
		"255 characters is within the glossary limit regardless of how many bytes they occupy")
}

// conformanceIssues extracts the individual issues from a validation error, and
// returns none when err is nil.
func conformanceIssues(t *testing.T, err error) []ValidationIssue {
	t.Helper()
	if err == nil {
		return nil
	}
	var ce *ConformanceError
	require.ErrorAs(t, err, &ce)
	return ce.Issues()
}

// A value supplied for a field that does not apply at that stage is an error,
// not a harmless extra: it is what a flattened "everything everywhere, carry it
// forward" schema produces.
func TestV16NonApplicableFieldsAreRejectedNotCarriedForward(t *testing.T) {
	s := v16Schema(t)

	cases := []struct {
		name  string
		stage Stage
		class EventClass
		field string
		value string
	}{
		{"CVE identifier at the 72-hour notification", StageNotification72h, EventClassAEV, FieldV16CVEID, "CVE-2026-31337"},
		{"CVE identifier at the final report", StageFinalReport, EventClassAEV, FieldV16CVEID, "CVE-2026-31337"},
		{"EUVD identifier at the final report", StageFinalReport, EventClassAEV, FieldV16EUVDID, "EUVD-2026-12345"},
		{"attack vector at early warning", StageEarlyWarning, EventClassAEV, FieldV16AttackVector, "network"},
		{"attack vector at the final report", StageFinalReport, EventClassAEV, FieldV16AttackVector, "network"},
		{"notification title at the final report", StageFinalReport, EventClassAEV, FieldV16Title, "Title"},
		{"PEC at early warning", StageEarlyWarning, EventClassAEV, FieldV16PEC, "a)"},
		{"PEC at the final report", StageFinalReport, EventClassAEV, FieldV16PEC, "a)"},
		{"incident awareness at 72 hours", StageNotification72h, EventClassSI, FieldV16IncidentAwareness, "2026-09-20 08:45 UTC"},
		{"incident occurrence at the final report", StageFinalReport, EventClassSI, FieldV16IncidentOccurred, "2026-09-19 00:00 UTC"},
		{"initial assessment at the final report", StageFinalReport, EventClassSI, FieldV16IncidentAssessment, "Preliminary"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := s.Validate(tc.stage, tc.class, Values{tc.field: tc.value})
			require.Error(t, err, "%s must not accept %s", tc.name, tc.field)
			var found bool
			for _, i := range conformanceIssues(t, err) {
				if i.FieldID == tc.field && strings.Contains(i.Problem, "does not apply") {
					found = true
				}
			}
			assert.True(t, found, "expected a not-applicable issue for %s, got: %v", tc.field, conformanceIssues(t, err))
		})
	}
}

// "Required if such information is available" and "copied from the previous step
// by default" are recorded as inherited-or-update: absence is not an error,
// because the value conditionally may not exist at all.
func TestV16ConditionalFieldsDoNotFailWhenAbsent(t *testing.T) {
	s := v16Schema(t)

	for _, tc := range []struct {
		field string
		stage Stage
		class EventClass
	}{
		{FieldV16Actor, StageFinalReport, EventClassAEV},
		{FieldV16AEVOccurred, StageNotification72h, EventClassAEV},
		{FieldV16IncidentSuspected, StageNotification72h, EventClassSI},
	} {
		f, ok := s.Field(tc.field)
		require.True(t, ok)
		require.Equal(t, RequirementInheritedOrUpdate, f.RequirementAt(tc.stage, tc.class),
			"%s must be inherited-or-update at %s/%s", tc.field, tc.class, tc.stage)

		// Absence of an inherited-or-update field is not itself a problem. The
		// issues slice must be non-empty, otherwise the loop below would pass
		// vacuously.
		issues := conformanceIssues(t, s.Validate(tc.stage, tc.class, Values{}))
		require.NotEmpty(t, issues, "an empty package must still report its missing required fields")
		for _, i := range issues {
			assert.False(t, i.FieldID == tc.field && strings.Contains(i.Problem, "but absent"),
				"%s must not be reported as a missing required field", tc.field)
		}
	}
}

// The awareness timestamp is the anchor every Article 14 deadline is computed
// from. The package must carry that same instant, not a separately-derived value
// that merely looks similar — so the round trip is asserted through the deadline
// calculation itself.
func TestV16AwarenessFieldCarriesTheDeadlineAnchor(t *testing.T) {
	s := v16Schema(t)

	awarenessAt := time.Date(2026, 9, 20, 8, 45, 0, 0, time.UTC)
	awareness := cra.Awareness{
		AwarenessAt: awarenessAt,
		Source:      cra.AwarenessSourceInternalTelemetry,
		Evidence:    "advisory snapshot sha256:aa11 export of feed entry 2026-09-20T08:41Z",
	}
	require.NoError(t, awareness.Validate())

	deadline, err := cra.DeadlineAt(cra.Anchors{Awareness: awareness}, cra.EventTypeAEV, cra.StageEarlyWarning)
	require.NoError(t, err)

	for _, class := range []EventClass{EventClassAEV, EventClassSI} {
		field, ok := AwarenessFieldFor(class)
		require.True(t, ok, "%s must have an awareness field", class)

		value := SRPTimestamp(awarenessAt)

		// The staged value must validate at early warning, where the glossary
		// makes it mandatory.
		values := Values{field: value}
		for _, i := range conformanceIssues(t, s.Validate(StageEarlyWarning, class, values)) {
			assert.NotEqual(t, field, i.FieldID,
				"the awareness value %q written into %s must pass the field's own format check: %s",
				value, field, i.Problem)
		}

		// And it must denote the same instant the deadline was computed from.
		// If this fails, the product tells a manufacturer one clock and files
		// another, which is the failure the whole awareness model exists to
		// prevent.
		parsed, err := ParseSRPTimestamp(value)
		require.NoError(t, err)
		assert.True(t, parsed.Equal(awarenessAt),
			"%s must carry the awareness instant itself, got %s for %s", field, parsed, awarenessAt)
		rederived, err := cra.DeadlineAt(cra.Anchors{Awareness: cra.Awareness{
			AwarenessAt: parsed,
			Source:      awareness.Source,
			Evidence:    awareness.Evidence,
		}}, cra.EventTypeAEV, cra.StageEarlyWarning)
		require.NoError(t, err)
		assert.True(t, rederived.Equal(deadline),
			"re-deriving the deadline from the filed value must give the filed deadline: %s vs %s", rederived, deadline)
	}
}

func TestSRPTimestampRoundTripsInTheGlossaryFormat(t *testing.T) {
	// The glossary prints "2026-08-24 09:15 UTC" as the expected value.
	instant := time.Date(2026, 8, 24, 9, 15, 0, 0, time.UTC)
	assert.Equal(t, "2026-08-24 09:15 UTC", SRPTimestamp(instant))

	parsed, err := ParseSRPTimestamp("2026-08-24 09:15 UTC")
	require.NoError(t, err)
	assert.True(t, parsed.Equal(instant))
	assert.Equal(t, time.UTC, parsed.Location())

	// A non-UTC instant is rendered in UTC rather than rejected, because the
	// glossary's format is UTC by definition.
	offset := time.Date(2026, 8, 24, 11, 15, 0, 0, time.FixedZone("CEST", 2*60*60))
	assert.Equal(t, "2026-08-24 09:15 UTC", SRPTimestamp(offset))

	_, err = ParseSRPTimestamp("last Tuesday")
	require.Error(t, err)
}

// The AEV and SI awareness fields are distinct published positions, and neither
// may be used for the other class.
func TestAwarenessFieldMappingIsPerEventClass(t *testing.T) {
	aev, ok := AwarenessFieldFor(EventClassAEV)
	require.True(t, ok)
	assert.Equal(t, "v26", aev)

	si, ok := AwarenessFieldFor(EventClassSI)
	require.True(t, ok)
	assert.Equal(t, "i37", si)

	_, ok = AwarenessFieldFor(EventClass("something_else"))
	assert.False(t, ok, "an unknown event class has no awareness field")

	s := v16Schema(t)
	f, ok := s.Field(aev)
	require.True(t, ok)
	assert.False(t, f.AppliesTo(EventClassSI), "v26 is AEV-only")
}

// A field's requirement cannot be weaker than "must be present" at a stage the
// glossary calls mandatory, in either direction.
func TestV16MandatoryFieldsAreRequiredNotOptional(t *testing.T) {
	s := v16Schema(t)

	for _, tc := range []struct {
		field string
		class EventClass
	}{
		{FieldV16AEVAwareness, EventClassAEV},
		{FieldV16IncidentAwareness, EventClassSI},
		{FieldV16IncidentSuspected, EventClassSI},
	} {
		f, ok := s.Field(tc.field)
		require.True(t, ok)
		assert.Equal(t, RequirementRequired, f.RequirementAt(StageEarlyWarning, tc.class),
			"%s is mandatory at early warning", tc.field)
	}

	// And the absence is reported, per field, not just as a count.
	err := s.Validate(StageEarlyWarning, EventClassAEV, Values{})
	missing := map[string]bool{}
	for _, i := range conformanceIssues(t, err) {
		if strings.Contains(i.Problem, "but absent") {
			missing[i.FieldID] = true
		}
	}
	assert.True(t, missing[FieldV16AEVAwareness], "the AEV awareness timestamp must be reported missing")
	assert.False(t, missing[FieldV16CVEID], "the CVE identifier is optional at early warning")
	assert.False(t, missing[FieldV16AttackVector], "the attack vector does not apply at early warning")
}
