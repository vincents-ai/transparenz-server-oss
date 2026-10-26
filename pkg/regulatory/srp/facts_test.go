// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.

package srp

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vincents-ai/transparenz-server-oss/pkg/regulatory"
)

func factsFixture() ReportFacts {
	mitigation := time.Date(2026, 9, 22, 14, 0, 0, 0, time.UTC)
	return ReportFacts{
		Title:                 "Actively exploited vulnerability CVE-2026-31337 in Example Gateway (libfoo)",
		Summary:               "An authentication bypass in the management interface is being exploited.",
		ProductName:           "Example Gateway",
		ProductVersion:        "4.0 to 4.2.1",
		ComponentName:         "libfoo",
		ComponentVersion:      "2.2.0",
		CVE:                   "CVE-2026-31337",
		EUVDID:                "EUVD-2026-12345",
		Actor:                 "Unknown actor; indicators in REF-2026-18",
		AttackVector:          "network",
		MitigationAvailableAt: &mitigation,
	}
}

// The report supplies what it actually records, so a filer is not re-typing it
// into a form where it can drift.
func TestDerivedFieldsComeFromTheReport(t *testing.T) {
	schema := v16(t)
	derived := deriveFields(schema, regulatory.StageEarlyWarning, regulatory.EventClassAEV, factsFixture())

	assert.Equal(t, "Vulnerability", derived[regulatory.FieldV16NotificationType])
	assert.Equal(t, factsFixture().Title, derived[regulatory.FieldV16Title])
	assert.Equal(t, factsFixture().Summary, derived[regulatory.FieldV16Summary])
	assert.Equal(t, "Example Gateway", derived[regulatory.FieldV16ProductName])
	assert.Equal(t, "4.0 to 4.2.1", derived[regulatory.FieldV16ProductVersion])
	assert.Equal(t, "libfoo 2.2.0", derived[regulatory.FieldV16ComponentName],
		"field 12 asks for the component and its version together")
	assert.Equal(t, "CVE-2026-31337", derived[regulatory.FieldV16CVEID])
	assert.Equal(t, "EUVD-2026-12345", derived[regulatory.FieldV16EUVDID])

	// The attack vector applies only at the 72-hour stage, and v22 only becomes
	// applicable later still, so neither is derived on an early warning.
	_, hasVector := derived[regulatory.FieldV16AttackVector]
	assert.False(t, hasVector, "field 18 is not applicable at early warning")
	_, hasMitigation := derived[regulatory.FieldV16MeasureDate]
	assert.False(t, hasMitigation,
		"v22 is gated on field 17 at this stage and is left to the filer")
}

// A derivation that ignored the stage would turn a helpful feature into a
// guaranteed submission failure: v1.6 marks most fields not applicable outside
// one or two stages.
func TestDerivedFieldsRespectThePerStageMatrix(t *testing.T) {
	schema := v16(t)

	finalReport := deriveFields(schema, regulatory.StageFinalReport, regulatory.EventClassAEV, factsFixture())
	for _, absent := range []string{
		regulatory.FieldV16NotificationType,
		regulatory.FieldV16Title,
		regulatory.FieldV16Summary,
		regulatory.FieldV16ProductName,
		regulatory.FieldV16CVEID,
	} {
		_, present := finalReport[absent]
		assert.False(t, present, "%s does not apply at the final report and must not be derived into it", absent)
	}
	assert.Equal(t, "2026-09-22 14:00 UTC", finalReport[regulatory.FieldV16MeasureDate],
		"v22 is required at the final report and the report holds the instant it asks for")

	notification := deriveFields(schema, regulatory.StageNotification72h, regulatory.EventClassAEV, factsFixture())
	assert.Equal(t, "network", notification[regulatory.FieldV16AttackVector],
		"field 18 applies at the 72-hour stage")
}

func TestDerivedNotificationTypeFollowsTheEventClass(t *testing.T) {
	schema := v16(t)

	aev := deriveFields(schema, regulatory.StageEarlyWarning, regulatory.EventClassAEV, ReportFacts{})
	assert.Equal(t, "Vulnerability", aev[regulatory.FieldV16NotificationType])

	si := deriveFields(schema, regulatory.StageEarlyWarning, regulatory.EventClassSI, ReportFacts{})
	assert.Equal(t, "Incident", si[regulatory.FieldV16NotificationType])
}

// An earlier schema does not define these positions, so nothing may be derived
// into it: a field the schema does not know about would fail validation for a
// reason that has nothing to do with the caller.
func TestDerivationIsSkippedForASchemaWithoutThePositions(t *testing.T) {
	v2, err := regulatory.BuildSRPGlossarySchemaV2("k", time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err)

	derived := deriveFields(v2, regulatory.StageEarlyWarning, regulatory.EventClassAEV, factsFixture())
	assert.Empty(t, derived)
}

// A caller who supplies a value that disagrees with the report is told so. The
// disagreement is the information: preferring either value silently means the
// filing and the case file differ with nobody aware.
func TestSuppliedValuesMustAgreeWithTheReport(t *testing.T) {
	schema := v16(t)
	awareness := awarenessAt()

	in := BuildInput{
		ReportID: uuid.New(), OrgID: uuid.New(),
		EventClass: regulatory.EventClassAEV, Stage: regulatory.StageEarlyWarning,
		CoordinatorID: "DE-CSIRT",
		Facts:         facts(),
		AwarenessAt:   &awareness,
		Now:           buildNow,
		Fields: map[string]string{
			regulatory.FieldV16ManufacturerName: "Example Manufacturing GmbH",
			regulatory.FieldV16MemberStates:     "Germany",
			// The report says "Example Gateway"; this says something else.
			regulatory.FieldV16ProductName: "Some Other Product",
		},
	}

	_, err := Build(schema, in)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDerivedFieldConflict)
	assert.Contains(t, err.Error(), regulatory.FieldV16ProductName)

	// Restating the report's own value is not a conflict.
	in.Fields[regulatory.FieldV16ProductName] = "Example Gateway"
	_, err = Build(schema, in)
	require.NoError(t, err)
}

// The end-to-end shape: a report that holds most of the form needs only the
// three fields it does not hold to produce a valid early warning.
func TestPackageBuildsFromReportFactsPlusTheGaps(t *testing.T) {
	schema := v16(t)
	awareness := awarenessAt()

	pkg, err := Build(schema, BuildInput{
		ReportID: uuid.New(), OrgID: uuid.New(),
		EventClass: regulatory.EventClassAEV, Stage: regulatory.StageEarlyWarning,
		CoordinatorID: "DE-CSIRT",
		Facts:         facts(),
		AwarenessAt:   &awareness,
		Now:           buildNow,
		Fields: map[string]string{
			// Not held by the report model today.
			regulatory.FieldV16ManufacturerName: "Example Manufacturing GmbH",
			regulatory.FieldV16MemberStates:     "Germany, Netherlands",
		},
	})
	require.NoError(t, err)

	// The product version IS held by the facts fixture, so this package needed
	// three inputs and the report supplied the rest.
	assert.Equal(t, "4.0 to 4.2.1", pkg.Fields[regulatory.FieldV16ProductVersion])
	assert.Equal(t, "Vulnerability", pkg.Fields[regulatory.FieldV16NotificationType])
	assert.Equal(t, regulatory.SRPTimestamp(awareness), pkg.Fields[regulatory.FieldV16AEVAwareness])
	assert.True(t, pkg.VerifyDigest())
}

// facts returns the fixture as a pointer for BuildInput.
func facts() *ReportFacts {
	f := factsFixture()
	return &f
}

// The written statements are carried from the report into the position the event
// class uses, so one text serves both classes and cannot differ between stages.
func TestWrittenStatementsAreDerivedPerEventClass(t *testing.T) {
	schema := v16(t)

	f := factsFixture()
	f.SeverityDescription = "Severity: High. Authentication validation missing in endpoint X."
	f.ImpactDescription = "Remote unauthenticated compromise of configuration data."
	f.MeasuresTaken = "Update 4.2.2 released; old releases withdrawn from the portal."
	f.MeasuresForUsers = "Install 4.2.2; restrict management access until then."
	f.GeneralInformation = "Authentication bypass in the management interface."
	f.InitialAssessment = "Confirmed impact is limited to three units."
	f.UpdateDetails = "Security update 4.2.2 corrects the missing authorisation check."
	f.RootCause = "Missing authorisation check introduced in 3.1.0."

	// An AEV final report: the AEV positions, and none of the SI ones.
	aev := deriveFields(schema, regulatory.StageFinalReport, regulatory.EventClassAEV, f)
	assert.Equal(t, f.SeverityDescription, aev[regulatory.FieldV16SeverityDesc])
	assert.Equal(t, f.ImpactDescription, aev[regulatory.FieldV16ImpactDesc])
	assert.Equal(t, f.UpdateDetails, aev[regulatory.FieldV16UpdateDetails])
	assert.Equal(t, f.MeasuresTaken, aev[regulatory.FieldV16MeasuresTaken])
	assert.Equal(t, f.MeasuresForUsers, aev[regulatory.FieldV16MeasuresForUsers])
	_, hasSISeverity := aev[regulatory.FieldV16IncidentSeverity]
	assert.False(t, hasSISeverity, "an AEV must not carry the severe-incident severity position")

	// A severe incident final report: the SI positions, from the same columns.
	si := deriveFields(schema, regulatory.StageFinalReport, regulatory.EventClassSI, f)
	assert.Equal(t, f.SeverityDescription, si[regulatory.FieldV16IncidentSeverity])
	assert.Equal(t, f.ImpactDescription, si[regulatory.FieldV16IncidentImpact])
	assert.Equal(t, f.MeasuresTaken, si[regulatory.FieldV16IncidentMeasures],
		"i33 is the severe-incident statement of the same fact")
	_, hasAEVSeverity := si[regulatory.FieldV16SeverityDesc]
	assert.False(t, hasAEVSeverity)

	// 17 and 14 apply to both classes; 14 only at the early warning.
	siEW := deriveFields(schema, regulatory.StageEarlyWarning, regulatory.EventClassSI, f)
	assert.Equal(t, f.MeasuresForUsers, siEW[regulatory.FieldV16MeasuresForUsers])
	assert.Equal(t, f.UserAction, siEW[regulatory.FieldV16UserAction])
	_, siFRHasUserAction := si[regulatory.FieldV16UserAction]
	assert.False(t, siFRHasUserAction, "field 14 applies at the early warning only")
}

// With the statements recorded on the report, the 72-hour and final-report stages
// need no supplied field at all beyond the PEC decision, which is a human choice
// the schema treats as optional.
func TestLaterStagesBuildEntirelyFromTheReport(t *testing.T) {
	schema := v16(t)

	f := factsFixture()
	f.SeverityDescription = "Severity: High."
	f.ImpactDescription = "Configuration data compromised."
	f.MeasuresTaken = "Update released."
	f.MeasuresForUsers = "Install the update."
	f.GeneralInformation = "Authentication bypass in the management interface."
	f.InitialAssessment = "Limited to three units."
	f.UpdateDetails = "Corrects the missing authorisation check."
	f.RootCause = "Missing authorisation check."

	for _, tc := range []struct {
		name  string
		stage regulatory.Stage
		class regulatory.EventClass
	}{
		{"AEV / 72h", regulatory.StageNotification72h, regulatory.EventClassAEV},
		{"AEV / final report", regulatory.StageFinalReport, regulatory.EventClassAEV},
		{"SI / 72h", regulatory.StageNotification72h, regulatory.EventClassSI},
		{"SI / final report", regulatory.StageFinalReport, regulatory.EventClassSI},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Build(schema, BuildInput{
				ReportID: uuid.New(), OrgID: uuid.New(),
				EventClass: tc.class, Stage: tc.stage,
				CoordinatorID: "DE-CSIRT",
				Facts:         &f,
				Now:           buildNow,
			})
			require.NoError(t, err, "the report holds everything this stage requires")
		})
	}
}
