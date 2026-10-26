// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.

package srp

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vincents-ai/transparenz-server-oss/pkg/regulatory"
	"github.com/vincents-ai/transparenz-server-oss/pkg/regulatory/cra"
)

var buildNow = time.Date(2026, 9, 20, 9, 30, 0, 0, time.UTC)

// v16 returns the transcription the builder is expected to be used with.
func v16(t *testing.T) *regulatory.ReportingSchema {
	t.Helper()
	s, err := regulatory.BuildSRPGlossaryV16Schema(
		"ENISA_OPERATIONAL_GUIDANCE|ENISA SRP Glossary|1.6",
		time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC),
	)
	require.NoError(t, err)
	return s
}

// completeAEVEarlyWarning is a field set that satisfies every required field of
// the AEV early warning in v1.6, except the awareness timestamp, which is
// supplied as an instant rather than as a field.
func completeAEVEarlyWarning() map[string]string {
	return map[string]string{
		regulatory.FieldV16NotificationType: "Vulnerability",
		regulatory.FieldV16Title:            "Active exploitation affecting Example Gateway 4.2",
		regulatory.FieldV16Summary:          "An actively exploited authentication bypass affects Example Gateway 4.2.",
		regulatory.FieldV16ManufacturerName: "Example Manufacturing GmbH",
		regulatory.FieldV16MemberStates:     "Germany",
		regulatory.FieldV16ProductName:      "Example Gateway",
		regulatory.FieldV16ProductVersion:   "4.0 to 4.2.1",
	}
}

func awarenessAt() time.Time { return time.Date(2026, 9, 20, 8, 45, 0, 0, time.UTC) }

func aevEarlyWarningInput(t *testing.T) BuildInput {
	t.Helper()
	awareness := awarenessAt()
	return BuildInput{
		ReportID:      uuid.New(),
		OrgID:         uuid.New(),
		EventClass:    regulatory.EventClassAEV,
		Stage:         regulatory.StageEarlyWarning,
		CoordinatorID: "DE-CSIRT",
		Fields:        completeAEVEarlyWarning(),
		AwarenessAt:   &awareness,
		Now:           buildNow,
	}
}

func TestBuildProducesASealedConformantPackage(t *testing.T) {
	schema := v16(t)
	p, err := Build(schema, aevEarlyWarningInput(t))
	require.NoError(t, err)

	assert.Equal(t, regulatory.SchemaIDSRPGlossaryV16, p.SchemaID)
	assert.Equal(t, "AEV", p.EventClass)
	assert.Equal(t, "early_warning", p.Stage)
	assert.Equal(t, "DE-CSIRT", p.CoordinatorID)
	assert.Equal(t, buildNow, p.GeneratedAt)
	assert.True(t, p.VerifyDigest(), "a freshly built package must verify against its own digest")
	assert.True(t, strings.HasPrefix(p.Digest, DigestPrefixV2),
		"new packages must be sealed under the current encoding, got %q", p.Digest)
}

// The reason Build exists: a package that the platform would reject must never
// acquire a digest, because a digest is what makes a filing record look verified.
func TestBuildRefusesAPackageThatWouldBeRejected(t *testing.T) {
	schema := v16(t)
	in := aevEarlyWarningInput(t)
	delete(in.Fields, regulatory.FieldV16ProductVersion)

	p, err := Build(schema, in)
	require.Error(t, err)
	assert.Empty(t, p.Digest, "a non-conformant package must not carry a digest")

	var ce *regulatory.ConformanceError
	require.ErrorAs(t, err, &ce, "the caller needs the individual issues to show the filer")
	var found bool
	for _, i := range ce.Issues() {
		if i.FieldID == regulatory.FieldV16ProductVersion && i.Stage == regulatory.StageEarlyWarning {
			found = true
		}
	}
	assert.True(t, found, "the missing product version must be reported against its own field and stage: %v", ce.Issues())
}

func TestBuildRefusesAFieldAtAStageWhereItDoesNotApply(t *testing.T) {
	schema := v16(t)

	// The CVE identifier exists only at early warning in v1.6; carrying it into
	// the 72-hour notification is not merely unnecessary, it is not applicable.
	in := BuildInput{
		ReportID: uuid.New(), OrgID: uuid.New(),
		EventClass:    regulatory.EventClassAEV,
		Stage:         regulatory.StageNotification72h,
		CoordinatorID: "DE-CSIRT",
		Fields: map[string]string{
			regulatory.FieldV16GeneralInfo: "Authentication bypass in the management interface.",
			regulatory.FieldV16CVEID:       "CVE-2026-31337",
		},
		Now: buildNow,
	}

	_, err := Build(schema, in)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not apply")
}

// The awareness instant the deadlines run from is the instant the package
// carries. Asserted through the deadline calculation, because the failure this
// prevents is the product telling a manufacturer one clock and filing another.
func TestBuildDerivesTheAwarenessFieldFromTheReportAnchor(t *testing.T) {
	schema := v16(t)
	in := aevEarlyWarningInput(t)
	p, err := Build(schema, in)
	require.NoError(t, err)

	filed := p.Fields[regulatory.FieldV16AEVAwareness]
	require.NotEmpty(t, filed, "the package must carry the anchor the deadlines are computed from")

	parsed, err := regulatory.ParseSRPTimestamp(filed)
	require.NoError(t, err)
	assert.True(t, parsed.Equal(*in.AwarenessAt),
		"the filed value %q must denote the report's awareness instant %s", filed, in.AwarenessAt)

	// The statutory deadline computed from the report and the one computed from
	// the filed value must be the same instant.
	evidence := "advisory snapshot sha256:aa11"
	fromReport, err := cra.DeadlineAt(cra.Anchors{Awareness: cra.Awareness{
		AwarenessAt: *in.AwarenessAt,
		Source:      cra.AwarenessSourceInternalTelemetry,
		Evidence:    evidence,
	}}, cra.EventTypeAEV, cra.StageEarlyWarning)
	require.NoError(t, err)

	fromFiled, err := cra.DeadlineAt(cra.Anchors{Awareness: cra.Awareness{
		AwarenessAt: parsed,
		Source:      cra.AwarenessSourceInternalTelemetry,
		Evidence:    evidence,
	}}, cra.EventTypeAEV, cra.StageEarlyWarning)
	require.NoError(t, err)

	assert.True(t, fromFiled.Equal(fromReport),
		"the deadline derived from the filed value must equal the filed deadline: %s vs %s", fromFiled, fromReport)
}

func TestBuildReportsAMissingAwarenessAnchorAsItsOwnProblem(t *testing.T) {
	schema := v16(t)
	in := aevEarlyWarningInput(t)
	in.AwarenessAt = nil

	_, err := Build(schema, in)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAwarenessAnchorMissing,
		"an absent awareness anchor is a legal-evidence problem, not a blank form field")
}

// Both event classes have their own published awareness position, and the
// builder must pick the right one rather than a shared "awareness" field.
func TestBuildUsesTheAwarenessFieldForTheEventClass(t *testing.T) {
	schema := v16(t)
	awareness := awarenessAt()

	si := BuildInput{
		ReportID: uuid.New(), OrgID: uuid.New(),
		EventClass: regulatory.EventClassSI, Stage: regulatory.StageEarlyWarning,
		CoordinatorID: "DE-CSIRT",
		Fields: map[string]string{
			regulatory.FieldV16NotificationType:  "Incident",
			regulatory.FieldV16Title:             "Update service compromise affecting Example Gateway",
			regulatory.FieldV16Summary:           "Unauthorised modification of the update package affected configuration integrity.",
			regulatory.FieldV16ManufacturerName:  "Example Manufacturing GmbH",
			regulatory.FieldV16MemberStates:      "Germany",
			regulatory.FieldV16ProductName:       "Example Gateway",
			regulatory.FieldV16ProductVersion:    "4.2.1",
			regulatory.FieldV16IncidentSuspected: "Yes. Evidence indicates intentional modification.",
		},
		AwarenessAt: &awareness,
		Now:         buildNow,
	}

	p, err := Build(schema, si)
	require.NoError(t, err)
	assert.Equal(t, regulatory.SRPTimestamp(awareness), p.Fields[regulatory.FieldV16IncidentAwareness])
	_, aevField := p.Fields[regulatory.FieldV16AEVAwareness]
	assert.False(t, aevField, "a severe incident must not carry the AEV awareness field")
}

func TestBuildRefusesToWriteTheAuthoritiessField(t *testing.T) {
	schema := v16(t)

	// Field 41 is optional at every stage, so a value for it would otherwise
	// validate cleanly. It is refused because the designated CSIRT writes it,
	// and a package sealed by us must not contain another party's record.
	in := aevEarlyWarningInput(t)
	in.Fields[regulatory.FieldV16CSIRTNote] = "Product distribution confirmed with the reporting party."

	p, err := Build(schema, in)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAuthorityAuthoredField)
	assert.Empty(t, p.Digest)

	// The assigned representative's note is ours to write, and must not be
	// refused by the same rule.
	in = aevEarlyWarningInput(t)
	in.Fields[regulatory.FieldV16ARNote] = "Forensic evidence will follow through the secure channel."
	_, err = Build(schema, in)
	require.NoError(t, err)
}

// A schema that cannot carry the anchor must say so rather than produce a
// package in which the instant silently went nowhere.
func TestBuildRefusesASchemaThatCannotCarryTheAnchor(t *testing.T) {
	// V2 has no awareness field: it was transcribed before the glossary stated
	// one as mandatory.
	v2, err := regulatory.BuildSRPGlossarySchemaV2("k", time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err)

	awareness := awarenessAt()
	_, err = Build(v2, BuildInput{
		ReportID: uuid.New(), OrgID: uuid.New(),
		EventClass: regulatory.EventClassAEV, Stage: regulatory.StageEarlyWarning,
		CoordinatorID: "DE-CSIRT",
		Fields:        map[string]string{},
		AwarenessAt:   &awareness,
		Now:           buildNow,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSchemaCannotCarryAwareness)
}

// The final report is a different document, not an append: the v1.6 form marks
// the early-warning fields not applicable at that stage.
func TestBuildTreatsTheFinalReportAsItsOwnFieldSet(t *testing.T) {
	schema := v16(t)

	finalReport := map[string]string{
		regulatory.FieldV16MeasuresTaken:    "Update 4.2.2 released; old releases withdrawn.",
		regulatory.FieldV16MeasuresForUsers: "Install version 4.2.2; restrict management access until then.",
		regulatory.FieldV16MeasureDate:      "2026-09-22 14:00 UTC",
		regulatory.FieldV16UpdateDetails:    "Security update 4.2.2 corrects the missing authorisation check.",
		regulatory.FieldV16SeverityDesc:     "Severity: High. Affected versions 4.0-4.2.1.",
		regulatory.FieldV16ImpactDesc:       "Remote unauthenticated compromise of configuration data.",
	}

	in := BuildInput{
		ReportID: uuid.New(), OrgID: uuid.New(),
		EventClass: regulatory.EventClassAEV, Stage: regulatory.StageFinalReport,
		CoordinatorID: "DE-CSIRT",
		Fields:        finalReport,
		Now:           buildNow,
	}
	p, err := Build(schema, in)
	require.NoError(t, err)
	assert.Len(t, p.Fields, len(finalReport), "the final report carries only its own fields")

	// Adding an early-warning field to the final report is a failure, not a
	// harmless extra.
	in.Fields[regulatory.FieldV16Title] = "Active exploitation affecting Example Gateway 4.2"
	_, err = Build(schema, in)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not apply")
}

func TestBuildIsDeterministicForIdenticalInput(t *testing.T) {
	schema := v16(t)
	in := aevEarlyWarningInput(t)

	first, err := Build(schema, in)
	require.NoError(t, err)
	second, err := Build(schema, in)
	require.NoError(t, err)
	assert.Equal(t, first.Digest, second.Digest,
		"the same input must seal to the same digest, or every retry looks like a changed package")

	// A single changed value must change the digest: that is what makes the
	// digest evidence of a specific document.
	in.Fields[regulatory.FieldV16Summary] = "Revised summary after further analysis."
	third, err := Build(schema, in)
	require.NoError(t, err)
	assert.NotEqual(t, first.Digest, third.Digest)
}

// Build must not mutate the caller's map: a handler that retries with the same
// input would otherwise find an awareness field it never supplied.
func TestBuildDoesNotMutateTheCallersFields(t *testing.T) {
	schema := v16(t)
	in := aevEarlyWarningInput(t)

	_, err := Build(schema, in)
	require.NoError(t, err)

	_, present := in.Fields[regulatory.FieldV16AEVAwareness]
	assert.False(t, present, "Build derived the awareness field into a copy, not into the caller's map")
}
