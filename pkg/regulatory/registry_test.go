// SPDX-FileCopyrightText: 2026 Vincent Palmer
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Transparenz, an open-source CRA compliance server.
// It is licensed under the GNU Affero General Public License v3.0; see LICENSE.

package regulatory

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var retrieved = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

// withFields copies base and adds the supplied key/value pairs.
func withFields(base Values, kv ...string) Values {
	out := Values{}
	for k, v := range base {
		out[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		out[kv[i]] = kv[i+1]
	}
	return out
}

func corpus(t *testing.T) (*Registry, *SchemaRegistry) {
	t.Helper()
	r, sr, err := BuildDefaultRegistry(retrieved)
	require.NoError(t, err)
	return r, sr
}

// --- provenance: sources are versioned and immutable ------------------------

func TestEverySourceIsPinnedToAVersionAndHash(t *testing.T) {
	r, _ := corpus(t)
	sources := r.Sources()
	require.NotEmpty(t, sources)
	for _, s := range sources {
		require.NoError(t, s.Validate(), "source %s is not citable", s.Key())
		assert.NotEmpty(t, s.Version)
		// Both digest forms are in use and both are legitimate: a label-derived
		// hash is bare hex, a retained artifact's hash carries the algorithm
		// prefix. Asserting a bare 64-character length here rejected the verifiable
		// source, which is exactly backwards — the check is that the digest is a
		// valid SHA-256, not that it is formatted the older way.
		bare, err := hexDigest(s.SourceHash)
		require.NoError(t, err, "source %s does not carry a valid SHA-256", s.Key())
		assert.Len(t, bare, 64)
	}
}

func TestSourceContentIsVerifiable(t *testing.T) {
	r, _ := corpus(t)
	s, ok := r.Source(AuthorityENISAOperationalGuidance, DocSRPGlossary, "1.3")
	require.True(t, ok)
	document := []byte(DocSRPGlossary + "|1.3")
	assert.True(t, s.VerifyHash(document))
	assert.False(t, s.VerifyHash([]byte("something else entirely")))
}

func TestRegisteringTheSameVersionWithDifferentContentIsRejected(t *testing.T) {
	r, _ := corpus(t)
	s, _ := r.Source(AuthorityENISAOperationalGuidance, DocSRPGlossary, "1.3")

	tampered := s
	tampered.SourceHash = ComputeSourceHash([]byte("a different document"))
	err := r.AddSource(tampered)
	require.Error(t, err, "a versioned source must not be silently redefined")

	// Re-adding the identical source is idempotent.
	require.NoError(t, r.AddSource(s))
}

func TestSupersedingRequiresThePriorVersionToExist(t *testing.T) {
	r := NewRegistry()
	base := Source{
		Authority: AuthorityENISAOperationalGuidance, Document: DocSRPGlossary, Version: "1.3",
		PublicationDate: time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC),
		RetrievedAt:     retrieved, EffectiveFrom: time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC),
		SourceHash: ComputeSourceHash([]byte("v1.3")),
	}
	next := Source{
		Authority: AuthorityENISAOperationalGuidance, Document: DocSRPGlossary, Version: "1.4",
		PublicationDate: time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC),
		RetrievedAt:     retrieved, EffectiveFrom: time.Date(2027, 1, 11, 0, 0, 0, 0, time.UTC),
		SourceHash: ComputeSourceHash([]byte("v1.4")), Supersedes: "1.3",
	}
	require.NoError(t, r.AddSource(next))
	err := r.Validate()
	require.Error(t, err, "a broken version chain must fail validation")
	assert.Contains(t, err.Error(), "version chain is broken")

	require.NoError(t, r.AddSource(base))
	require.NoError(t, r.Validate())
}

func TestCurrentSourceIsTheNewestEffectiveNotTheNewestPublished(t *testing.T) {
	r, _ := corpus(t)
	// A document published in 2026 for effect in 2027 must not become current
	// in 2026.
	future := Source{
		Authority: AuthorityENISAOperationalGuidance, Document: DocSRPGlossary, Version: "1.4",
		PublicationDate: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
		RetrievedAt:     retrieved, EffectiveFrom: time.Date(2027, 1, 11, 0, 0, 0, 0, time.UTC),
		SourceHash: ComputeSourceHash([]byte("v1.4")), Supersedes: "1.3",
	}
	require.NoError(t, r.AddSource(future))

	current, ok := r.CurrentSource(AuthorityENISAOperationalGuidance, DocSRPGlossary, retrieved)
	require.True(t, ok)
	assert.Equal(t, "1.3", current.Version)

	later, ok := r.CurrentSource(AuthorityENISAOperationalGuidance, DocSRPGlossary,
		time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC))
	require.True(t, ok)
	assert.Equal(t, "1.4", later.Version)
}

func TestVersionHistoryRemainsQueryable(t *testing.T) {
	r, _ := corpus(t)
	// Two glossary versions ship: 1.3, which the V1 and V2 schemas were
	// transcribed from, and 1.6, which the current schema cites. Both remain — a
	// report validated against 1.3 stays explainable after 1.6 exists.
	versions := r.SourceVersions(AuthorityENISAOperationalGuidance, DocSRPGlossary)
	require.Len(t, versions, 2)
	assert.Equal(t, []string{"1.3", "1.6"}, []string{versions[0].Version, versions[1].Version})

	// Adding a further version keeps all three rather than replacing any.
	future := Source{
		Authority: AuthorityENISAOperationalGuidance, Document: DocSRPGlossary, Version: "1.7",
		PublicationDate: time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC),
		RetrievedAt:     retrieved, EffectiveFrom: time.Date(2027, 1, 11, 0, 0, 0, 0, time.UTC),
		SourceHash: ComputeSourceHash([]byte("v1.7")), Supersedes: "1.6",
	}
	require.NoError(t, r.AddSource(future))
	assert.Len(t, r.SourceVersions(AuthorityENISAOperationalGuidance, DocSRPGlossary), 3)
}

// --- authority: law is not guidance ---------------------------------------

func TestOnlyLawAndActsBind(t *testing.T) {
	assert.True(t, AuthorityLaw.Binding())
	assert.True(t, AuthorityDelegatedAct.Binding())
	assert.True(t, AuthorityImplementingAct.Binding())

	for _, a := range []Authority{
		AuthorityCommissionGuidance,
		AuthorityENISAOperationalGuidance,
		AuthorityStandard,
		AuthorityNationalGuidance,
		AuthorityTransparenzInterpretation,
	} {
		assert.False(t, a.Binding(), "%s must not be treated as binding law", a)
	}
}

func TestArticle14ObligationIsAnchoredInTheRegulationNotInEnisaGuidance(t *testing.T) {
	r, _ := corpus(t)
	o, ok := r.Obligation(ObligationCRAArticle14Report)
	require.True(t, ok)

	assert.Equal(t, AuthorityLaw, o.Authority)
	assert.Equal(t, InstrumentCRA, o.Instrument)
	assert.Equal(t, "Article 14", o.Article)

	// ENISA's glossary and the Commission's guidance inform the implementation
	// but are not the legal basis. Both glossary versions remain cited: the older
	// one still explains reports filed against the schemas transcribed from it.
	require.Len(t, o.Guidance, 4)
	for _, g := range o.Guidance {
		src, ok := r.SourceByKey(g)
		require.True(t, ok)
		assert.False(t, src.Authority.Binding(), "%s is cited as guidance and must not bind", g)
	}
	assert.Contains(t, o.Interpretation, "not from the Regulation")
}

func TestGuidanceCannotBeRegisteredAsTheLegalBasisOfAnObligation(t *testing.T) {
	r, _ := corpus(t)
	guidanceKey := Source{
		Authority: AuthorityENISAOperationalGuidance, Document: DocSRPGlossary, Version: "1.3",
	}.Key()

	err := r.AddObligation(Obligation{
		ID:          "BAD-OBLIGATION",
		Authority:   AuthorityENISAOperationalGuidance,
		SourceKey:   guidanceKey,
		AppliesFrom: retrieved,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "non-binding")
}

func TestBindingSourceCannotBeListedAsGuidance(t *testing.T) {
	r, _ := corpus(t)
	err := r.AddObligation(Obligation{
		ID:          "BAD-OBLIGATION-2",
		Authority:   AuthorityLaw,
		SourceKey:   Source{Authority: AuthorityLaw, Document: InstrumentCRA, Version: "consolidated-2026-09-11"}.Key(),
		Guidance:    []string{Source{Authority: AuthorityLaw, Document: InstrumentCRA, Version: "consolidated-2026-09-11"}.Key()},
		AppliesFrom: retrieved,
	})
	require.Error(t, err)
}

func TestObligationCannotCiteAnUnregisteredSource(t *testing.T) {
	r := NewRegistry()
	err := r.AddObligation(Obligation{
		ID:          "ORPHAN",
		Authority:   AuthorityLaw,
		SourceKey:   "LAW|nonexistent|1.0",
		AppliesFrom: retrieved,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unregistered source")
}

func TestCorpusRegistryValidatesCleanly(t *testing.T) {
	r, _ := corpus(t)
	require.NoError(t, r.Validate())
}

func TestArticle14ObligationIsEffectiveFromEleventhSeptemberTwentyTwentySix(t *testing.T) {
	r, _ := corpus(t)
	o, _ := r.Obligation(ObligationCRAArticle14Report)
	assert.Equal(t, "2026-09-11T00:00:00Z", o.AppliesFrom.Format(time.RFC3339))
}

// --- ENISA SRP glossary schema ---------------------------------------------

func TestCurrentSchemaIsTheGlossaryTranscriptionInForce(t *testing.T) {
	_, sr := corpus(t)

	s, err := sr.Current(RegimeCRAArticle14)
	require.NoError(t, err)
	assert.Equal(t, SchemaIDSRPGlossaryV16, s.ID,
		"new work must validate against the glossary in force, not against an earlier corrected one")
	assert.Contains(t, s.SourceKey, "|1.6",
		"the current schema must cite the source version it was transcribed from")

	// The earlier versions must still be registered and retrievable, unchanged,
	// so packages and reports already generated under them stay interpretable.
	// This is the acceptance criterion that a schema migration must never
	// reinterpret historical data.
	v1, ok := sr.Schema(SchemaIDSRPGlossaryV1)
	require.True(t, ok, "V1 must remain registered for historical reports")
	v1Closure, ok := v1.Field(FieldClosure)
	require.True(t, ok, "V1 must keep its own meaning for v19")
	assert.Equal(t, FieldClosure, v1Closure.ID,
		"under V1, v19 is reporting closure and must NOT be reinterpreted as a CVE")

	v2, ok := sr.Schema(SchemaIDSRPGlossaryV2)
	require.True(t, ok, "V2 must remain registered for reports filed under it")
	v2CVE, ok := v2.Field(FieldCVEID)
	require.True(t, ok)
	assert.Equal(t, "v19", v2CVE.IdentifierPosition, "under V2, v19 is the CVE identifier")

	// Under v1.6, v19 is the CVE identifier as published, and the concepts that
	// never had a glossary position are gone rather than renumbered. A record's
	// own schema id decides which meaning applies, which is why nothing above is
	// repointed in place.
	v16CVE, ok := s.Field(FieldV16CVEID)
	require.True(t, ok)
	assert.True(t, v16CVE.IdentifierSourced)
	assert.Equal(t, RequirementOptional, v16CVE.RequirementAt(StageEarlyWarning, EventClassAEV),
		"the published glossary has the CVE identifier optional at early warning")
	// The three fields that never had a glossary position are gone from the v1.6
	// schema. Checked by NAME rather than by the old constants' values, because
	// those values now collide with real published positions — FieldClosure is
	// "v19", which v1.6 uses for the CVE identifier. A value-based check here
	// would test nothing.
	phantomNames := map[string]bool{
		"Evidence of active exploitation":  true,
		"Remediation and recovery outcome": true,
		"Reporting closure":                true,
	}
	for _, f := range s.Fields() {
		assert.False(t, phantomNames[f.Name],
			"field %q (%s) has no position in any published glossary and must not appear in the v1.6 schema", f.Name, f.ID)
	}
	require.Equal(t, len(srp16Matrix), len(s.Fields()),
		"the schema must contain exactly the %d fields the matrix lists", len(srp16Matrix))
}

// The six ENISA conformance fixtures the brief calls for: every combination of
// event class and stage must be validatable, and a complete package for each
// must pass.
func TestENISAConformanceFixtures(t *testing.T) {
	_, sr := corpus(t)
	s, err := sr.Current(RegimeCRAArticle14)
	require.NoError(t, err)

	// The v1.6 form is NOT cumulative with everything optional later: most fields
	// are not applicable outside one or two stages. Each fixture therefore holds
	// only the fields that apply at its own stage, which is what makes this a
	// test of the matrix rather than of the validator's tolerance. Supplying the
	// early-warning fields on a final report is an error, and the fixtures below
	// would fail if the matrix were flattened back to "everything everywhere".
	commonEW := Values{
		FieldV16Title:            "Active exploitation affecting Example Gateway 4.2",
		FieldV16Summary:          "An actively exploited authentication bypass affects Example Gateway 4.2. A workaround is published and an update is in preparation.",
		FieldV16ManufacturerName: "Example Manufacturing GmbH",
		FieldV16MemberStates:     "Germany; Netherlands",
		FieldV16ProductName:      "Example Gateway",
		FieldV16ProductVersion:   "4.0 to 4.2.1",
	}
	aevEW := withFields(commonEW,
		FieldV16NotificationType, "Vulnerability",
		FieldV16CVEID, "CVE-2026-31337",
		FieldV16AEVAwareness, "2026-09-20 08:45 UTC",
	)
	aev72 := Values{
		FieldV16GeneralInfo:  "Authentication bypass in the management interface allows a remote actor with network access to execute privileged actions.",
		FieldV16AttackVector: "Remote network access through an exposed API.",
		FieldV16MeasureDate:  "2026-09-22 14:00 UTC",
	}
	aevFinal := Values{
		FieldV16MeasuresTaken:    "Update 4.2.2 released; old releases withdrawn from the download portal.",
		FieldV16MeasuresForUsers: "Install version 4.2.2. Until then, restrict management-interface access to trusted networks.",
		FieldV16MeasureDate:      "2026-09-22 14:00 UTC",
		FieldV16UpdateDetails:    "Security update 4.2.2 corrects the missing authorisation check.",
		FieldV16SeverityDesc:     "Missing authorisation validation in endpoint X. Severity: High. Affected versions 4.0-4.2.1.",
		FieldV16ImpactDesc:       "Remote unauthenticated compromise of product configuration data on affected units.",
	}
	siEW := withFields(commonEW,
		FieldV16NotificationType, "Incident",
		FieldV16IncidentSuspected, "Yes. Evidence indicates an intentional unauthorised modification of the update package.",
		FieldV16IncidentAwareness, "2026-09-20 08:45 UTC",
	)
	si72 := Values{
		FieldV16IncidentNature:     "Malicious code executed through the update service and affected the integrity of locally stored configuration data.",
		FieldV16IncidentAssessment: "Confirmed impact is limited to configuration integrity on three product instances; broader exposure remains under investigation.",
	}
	siFinal := Values{
		FieldV16MeasuresTaken:     "Update distribution suspended; signing keys rotated; affected units isolated.",
		FieldV16MeasuresForUsers:  "Verify the signature of update packages; reinstall from the published checksum list.",
		FieldV16IncidentMeasures:  "Containment applied and monitoring extended to all update endpoints.",
		FieldV16IncidentSeverity:  "Low. Limited impact, no significant disruption to operation.",
		FieldV16IncidentImpact:    "Minimal. No material impact on operations, users or data.",
		FieldV16IncidentRootCause: "Supply-chain compromise through an unauthorised modification to the update package.",
	}

	fixtures := []struct {
		name   string
		class  EventClass
		stage  Stage
		values Values
	}{
		{"AEV / early warning", EventClassAEV, StageEarlyWarning, aevEW},
		{"AEV / 72h notification", EventClassAEV, StageNotification72h, aev72},
		{"AEV / final report", EventClassAEV, StageFinalReport, aevFinal},
		{"SI / early warning", EventClassSI, StageEarlyWarning, siEW},
		{"SI / 72h notification", EventClassSI, StageNotification72h, si72},
		{"SI / final report", EventClassSI, StageFinalReport, siFinal},
	}
	require.Len(t, fixtures, 6, "the conformance matrix is 2 event classes x 3 stages")

	for _, fx := range fixtures {
		t.Run(fx.name, func(t *testing.T) {
			require.NoError(t, s.Validate(fx.stage, fx.class, fx.values))
		})
	}
}

func TestEveryRequiredFieldIsRepresentableInternally(t *testing.T) {
	// The brief's CI requirement: fail if a required reporting field cannot be
	// represented. Asserted here as "every required field has a name, a format
	// and a source pin" across all six combinations.
	_, sr := corpus(t)
	s, err := sr.Current(RegimeCRAArticle14)
	require.NoError(t, err)

	for _, class := range []EventClass{EventClassAEV, EventClassSI} {
		for _, stage := range SchemaStages {
			required := s.RequiredFields(stage, class)
			assert.NotEmpty(t, required, "%s/%s has no required fields, which cannot be right", class, stage)
			for _, f := range required {
				assert.NotEmpty(t, f.Name, "%s is required at %s/%s but has no name", f.ID, class, stage)
				assert.NotEmpty(t, f.Format, "%s is required at %s/%s but has no format", f.ID, class, stage)
				assert.NotEmpty(t, f.SourceKey, "%s is not pinned to a source version", f.ID)
				// A required field whose identifier this codebase invented is a field
				// that cannot be checked against the published glossary, which is the
				// defect the v1.6 transcription exists to remove.
				assert.True(t, f.IdentifierSourced,
					"%s is required at %s/%s but its identifier is not transcribed from the glossary", f.ID, class, stage)
				assert.NotEmpty(t, f.IdentifierPosition,
					"%s is marked sourced at %s/%s but carries no glossary position", f.ID, class, stage)
			}
		}
	}
}

func TestMissingRequiredFieldIsReportedWithTheStageAndClass(t *testing.T) {
	_, sr := corpus(t)
	s, _ := sr.Current(RegimeCRAArticle14)

	incomplete := Values{
		FieldV16Title: "Active exploitation affecting Example Gateway 4.2",
	}
	err := s.Validate(StageEarlyWarning, EventClassAEV, incomplete)
	require.Error(t, err)

	var ce *ConformanceError
	require.ErrorAs(t, err, &ce)
	missing := map[string]bool{}
	// Build the expected problem text from the schema's OWN id. This test used
	// to hardcode "required by ENISA-SRP-1.3 but absent", which meant it silently
	// matched nothing once a second schema version was registered and every
	// assertion below passed vacuously against an empty map. A test that
	// depends on a literal embedded in a message will not fail when the message
	// changes; it will quietly stop testing.
	requiredAbsent := "required by " + s.ID + " but absent"
	for _, i := range ce.Issues() {
		if i.Problem == requiredAbsent {
			missing[i.FieldID] = true
		}
	}
	if len(missing) == 0 {
		t.Fatalf("no issues matched %q; the assertion below would pass vacuously. Issues: %v",
			requiredAbsent, ce.Issues())
	}

	// The CVE identifier is NOT among the missing-required fields: an
	// organisation frequently learns of an active exploitation before any CVE
	// exists, and refusing the report for that reason would be the worst
	// possible failure.
	assert.False(t, missing[FieldV16CVEID],
		"a CVE identifier must not be required at early warning; the glossary has it optional")
	// The awareness timestamp IS required: it is the anchor every Article 14
	// deadline is computed from, and v1.6 makes it mandatory at early warning.
	assert.True(t, missing[FieldV16AEVAwareness],
		"the awareness timestamp is mandatory at early warning and its absence must be reported")
	assert.Greater(t, len(ce.Issues()), 1, "every problem is reported, not just the first")
}

// The case that motivated relaxing the requirement: a lawful early warning
// with no CVE assigned must still validate.
func TestEarlyWarningWithoutACVEStillValidates(t *testing.T) {
	_, sr := corpus(t)
	s, _ := sr.Current(RegimeCRAArticle14)

	values := Values{
		FieldV16NotificationType: "Vulnerability",
		FieldV16Title:            "Active exploitation affecting Example Gateway 4.2",
		FieldV16Summary:          "Actively exploited authentication bypass; workaround published.",
		FieldV16ManufacturerName: "Example Manufacturing GmbH",
		FieldV16MemberStates:     "Germany",
		FieldV16ProductName:      "Example Gateway",
		FieldV16ProductVersion:   "4.0 to 4.2.1",
		FieldV16AEVAwareness:     "2026-09-20 08:45 UTC",
	}
	err := s.Validate(StageEarlyWarning, EventClassAEV, values)
	require.NoError(t, err,
		"an actively exploited vulnerability discovered before a CVE is assigned "+
			"is exactly what Article 14 early warning exists to report")
}

// Relaxing the requirement must not make the field unreportable: it is still
// applicable, still validated when present, and still carried forward.
func TestCVEIDRemainsApplicableAndOptional(t *testing.T) {
	_, sr := corpus(t)
	s, _ := sr.Current(RegimeCRAArticle14)

	f, ok := s.Field(FieldV16CVEID)
	require.True(t, ok, "the CVE identifier field must still exist under its published position")
	assert.Equal(t, RequirementOptional, f.RequirementAt(StageEarlyWarning, EventClassAEV))
	assert.Equal(t, EventClassAEV, f.ApplicableTo[0],
		"the field applies to actively exploited vulnerabilities only; v1.6 lists it as AEV")
	// v1.6 makes the identifier available at early warning only. A CVE on a
	// 72-hour notification is not merely unnecessary, it is not applicable, and
	// the validator reports it rather than silently carrying it forward.
	assert.Equal(t, RequirementNotApplicable, f.RequirementAt(StageNotification72h, EventClassAEV))
	assert.False(t, f.AppliesTo(EventClassSI),
		"v1.6 lists the CVE identifier as AEV-only; a severe incident has no CVE field")

	// Still reportable when supplied.
	values := Values{
		FieldV16NotificationType: "Vulnerability",
		FieldV16Title:            "Active exploitation affecting Example Gateway 4.2",
		FieldV16Summary:          "Actively exploited authentication bypass.",
		FieldV16ManufacturerName: "Example Manufacturing GmbH",
		FieldV16MemberStates:     "Germany",
		FieldV16ProductName:      "Example Gateway",
		FieldV16ProductVersion:   "4.0 to 4.2.1",
		FieldV16AEVAwareness:     "2026-09-20 08:45 UTC",
		FieldV16CVEID:            "CVE-2026-31337",
	}
	require.NoError(t, s.Validate(StageEarlyWarning, EventClassAEV, values))

	// The value IS format-checked: an identifier field rejects a malformed
	// value, so a typo is caught before a human files the report rather than by
	// the platform afterwards. (An earlier version of this test asserted the
	// opposite and passed only because "not-a-cve" happens to satisfy the bare
	// alphanumeric alternative of the identifier pattern — the assertion was
	// checking the wrong thing.)
	bad := withFields(values, FieldV16CVEID, "CVE-2026-31337!")
	require.Error(t, s.Validate(StageEarlyWarning, EventClassAEV, bad),
		"a malformed identifier must be rejected")
}

func TestAFieldFromTheOtherEventClassIsNotApplicable(t *testing.T) {
	_, sr := corpus(t)
	s, _ := sr.Current(RegimeCRAArticle14)

	// A CVE identifier is an AEV concept; supplying one on a severe incident
	// report is reported rather than silently accepted.
	err := s.Validate(StageEarlyWarning, EventClassSI, Values{
		FieldV16CVEID: "CVE-2026-31337",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not apply")
}

func TestEnforcedEnumValuesAreChecked(t *testing.T) {
	_, sr := corpus(t)
	s, _ := sr.Current(RegimeCRAArticle14)

	values := Values{
		FieldV16NotificationType: "Exploit",
	}
	err := s.Validate(StageEarlyWarning, EventClassAEV, values)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is not one of")
}

func TestDateFormatIsChecked(t *testing.T) {
	_, sr := corpus(t)
	s, _ := sr.Current(RegimeCRAArticle14)
	values := Values{FieldV16AEVAwareness: "some time on Tuesday"}
	err := s.Validate(StageEarlyWarning, EventClassAEV, values)
	require.Error(t, err, "an identifier field is format-checked")
}

func TestUnrecognisedFieldIsReported(t *testing.T) {
	_, sr := corpus(t)
	s, _ := sr.Current(RegimeCRAArticle14)
	err := s.Validate(StageEarlyWarning, EventClassAEV, Values{"v999": "something"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not defined in")
}

func TestSchemasAreImmutableAndVersionHistoryIsRetained(t *testing.T) {
	_, sr := corpus(t)
	s, _ := sr.Current(RegimeCRAArticle14)

	conflict := ReportingField{
		ID: FieldV16CVEID, Name: "Something else", Format: FormatText,
		ApplicableTo: []EventClass{EventClassAEV}, SourceKey: s.SourceKey,
	}
	require.Error(t, s.AddField(conflict), "a published field definition cannot be redefined")

	// A future glossary version registers alongside rather than replacing. Its
	// date must be later than every registered version, otherwise the assertion
	// below would be about the registry's existing contents rather than about
	// the one it just added.
	future, err := BuildSRPGlossarySchema(s.SourceKey, time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	future.ID = "ENISA-SRP-1.7"
	require.NoError(t, sr.Register(future))

	old, err := sr.SchemaAt(RegimeCRAArticle14, time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	assert.Equal(t, SchemaIDSRPGlossaryV1, old.ID, "a package validated under V1 stays explainable")

	mid, err := sr.SchemaAt(RegimeCRAArticle14, time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	assert.Equal(t, SchemaIDSRPGlossaryV16, mid.ID,
		"between the v1.6 publication and the next version, v1.6 is what was in force")

	current, err := sr.SchemaAt(RegimeCRAArticle14, time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	assert.Equal(t, "ENISA-SRP-1.7", current.ID)
}

func TestAFieldDeclaringARequirementForAnInapplicableClassIsRejected(t *testing.T) {
	s, err := BuildSRPGlossarySchema("ENISA_OPERATIONAL_GUIDANCE|ENISA SRP Glossary|1.3", retrieved)
	require.NoError(t, err)
	err = s.AddField(ReportingField{
		ID: "bad", Name: "Bad field", Format: FormatText,
		ApplicableTo: []EventClass{EventClassAEV},
		Stages: []StageRequirement{
			{StageEarlyWarning, EventClassSI, RequirementRequired},
		},
		SourceKey: s.SourceKey,
	})
	require.Error(t, err)
}

func TestRequirementDefaultsToNotApplicableRatherThanOptional(t *testing.T) {
	// Silently defaulting an unstated combination to optional would drop
	// required data.
	f := ReportingField{
		ID: "x", Name: "x", Format: FormatText,
		ApplicableTo: []EventClass{EventClassAEV},
		Stages: []StageRequirement{
			{StageEarlyWarning, EventClassAEV, RequirementRequired},
		},
	}
	assert.Equal(t, RequirementNotApplicable, f.RequirementAt(StageFinalReport, EventClassAEV))
	assert.Equal(t, RequirementNotApplicable, f.RequirementAt(StageEarlyWarning, EventClassSI))
}
