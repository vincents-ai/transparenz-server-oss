// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.

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
		assert.Len(t, s.SourceHash, 64)
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
	versions := r.SourceVersions(AuthorityENISAOperationalGuidance, DocSRPGlossary)
	require.Len(t, versions, 1)
	// With a successor registered, both remain — a report validated against
	// 1.3 stays explainable after 1.4 exists.
	future := Source{
		Authority: AuthorityENISAOperationalGuidance, Document: DocSRPGlossary, Version: "1.4",
		PublicationDate: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
		RetrievedAt:     retrieved, EffectiveFrom: time.Date(2027, 1, 11, 0, 0, 0, 0, time.UTC),
		SourceHash: ComputeSourceHash([]byte("v1.4")), Supersedes: "1.3",
	}
	require.NoError(t, r.AddSource(future))
	assert.Len(t, r.SourceVersions(AuthorityENISAOperationalGuidance, DocSRPGlossary), 2)
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
	// but are not the legal basis.
	require.Len(t, o.Guidance, 3)
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

func TestSchemaIsPinnedToGlossaryVersionOnePointThree(t *testing.T) {
	_, sr := corpus(t)
	s, err := sr.Current(RegimeCRAArticle14)
	require.NoError(t, err)
	assert.Equal(t, "ENISA-SRP-1.3", s.ID)
	assert.Equal(t, "1.3", s.SourceKey[len(s.SourceKey)-3:])
}

// The six ENISA conformance fixtures the brief calls for: every combination of
// event class and stage must be validatable, and a complete package for each
// must pass.
func TestENISAConformanceFixtures(t *testing.T) {
	_, sr := corpus(t)
	s, err := sr.Current(RegimeCRAArticle14)
	require.NoError(t, err)

	// A final report is cumulative: it carries the notification's facts forward
	// and adds the outcome and closure facts. The closure field is the one that
	// genuinely does not apply at earlier stages, so the fixtures are built
	// stage-aware rather than from one shared map — a single map would supply
	// a closure date on an early warning and the validator would rightly
	// reject it.
	aevCore := Values{
		FieldCVEID:        "CVE-2026-31337",
		FieldExploitation: "Observed mass exploitation of the authentication bypass; artefact pcap-2026-09-20-0845",
		FieldSeverity:     "Remote unauthenticated compromise of product data",
		FieldAttackVector: "network",
		FieldProduct:      "Example Gateway 3.x (all versions below 3.1.4), incl. embedded libfoo 2.2",
		FieldMitigation:   "none available at time of early warning",
	}
	siCore := Values{
		FieldSeverity:           "Loss of confidentiality and integrity of product data",
		FieldProduct:            "Example Gateway 3.1.2",
		FieldIncidentNature:     "Unauthorised access to the management interface",
		FieldImpact:             "Administrative credentials exposed on 41 installed units",
		FieldIncidentMitigation: "WAF rule deployed; firmware fix pending",
		FieldRootCause:          "Missing authorisation check introduced in 3.1.0",
	}
	aevFinal := withFields(aevCore,
		FieldOutcome, "3.1.4 deployed to all managed units; exploitation ceased 6 days after publication",
		FieldClosure, "2026-10-12")
	siFinal := withFields(siCore,
		FieldOutcome, "3.1.5 shipped and rolled out to 41 units; credentials rotated",
		FieldClosure, "2026-10-15")

	fixtures := []struct {
		name   string
		class  EventClass
		stage  Stage
		values Values
	}{
		{"AEV / early warning", EventClassAEV, StageEarlyWarning, aevCore},
		{"AEV / 72h notification", EventClassAEV, StageNotification72h, aevCore},
		{"AEV / final report", EventClassAEV, StageFinalReport, aevFinal},
		{"SI / early warning", EventClassSI, StageEarlyWarning, siCore},
		{"SI / 72h notification", EventClassSI, StageNotification72h, siCore},
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
			}
		}
	}
}

func TestMissingRequiredFieldIsReportedWithTheStageAndClass(t *testing.T) {
	_, sr := corpus(t)
	s, _ := sr.Current(RegimeCRAArticle14)

	incomplete := Values{
		FieldSeverity:     "Remote compromise",
		FieldAttackVector: "network",
		FieldProduct:      "Example Gateway 3.x",
	}
	err := s.Validate(StageEarlyWarning, EventClassAEV, incomplete)
	require.Error(t, err)

	var ce *ConformanceError
	require.ErrorAs(t, err, &ce)
	missing := map[string]bool{}
	for _, i := range ce.Issues() {
		if i.Problem == "required by ENISA-SRP-1.3 but absent" {
			missing[i.FieldID] = true
		}
	}
	assert.True(t, missing[FieldCVEID])
	assert.True(t, missing[FieldExploitation])
	assert.Greater(t, len(ce.Issues()), 1, "every problem is reported, not just the first")
}

func TestAFieldFromTheOtherEventClassIsNotApplicable(t *testing.T) {
	_, sr := corpus(t)
	s, _ := sr.Current(RegimeCRAArticle14)

	// A CVE identifier is an AEV concept; supplying one on a severe incident
	// report is reported rather than silently accepted.
	err := s.Validate(StageEarlyWarning, EventClassSI, Values{
		FieldSeverity:       "Loss of confidentiality",
		FieldProduct:        "Example Gateway 3.1.2",
		FieldIncidentNature: "Unauthorised management access",
		FieldImpact:         "Credentials exposed",
		FieldCVEID:          "CVE-2026-31337",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not apply")
}

func TestEnforcedEnumValuesAreChecked(t *testing.T) {
	_, sr := corpus(t)
	s, _ := sr.Current(RegimeCRAArticle14)

	values := Values{
		FieldCVEID: "CVE-2026-31337", FieldExploitation: "observed",
		FieldSeverity: "remote compromise", FieldProduct: "Gateway 3.x",
	}
	values[FieldAttackVector] = "carrier_pigeon"
	err := s.Validate(StageEarlyWarning, EventClassAEV, values)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is not one of")
}

func TestDateFormatIsChecked(t *testing.T) {
	_, sr := corpus(t)
	s, _ := sr.Current(RegimeCRAArticle14)
	values := Values{FieldCVEID: "CVE-2026-31337", FieldSeverity: "x", FieldAttackVector: "network", FieldProduct: "y", FieldExploitation: "z"}
	values[FieldEUVDID] = "not an identifier!"
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
		ID: FieldCVEID, Name: "Something else", Format: FormatText,
		ApplicableTo: []EventClass{EventClassAEV}, SourceKey: s.SourceKey,
	}
	require.Error(t, s.AddField(conflict), "a published field definition cannot be redefined")

	// A future glossary version registers alongside rather than replacing.
	v14, err := BuildSRPGlossarySchema(s.SourceKey, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	v14.ID = "ENISA-SRP-1.4"
	require.NoError(t, sr.Register(v14))

	old, err := sr.SchemaAt(RegimeCRAArticle14, time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	assert.Equal(t, "ENISA-SRP-1.3", old.ID, "a package validated in March stays explainable")

	current, err := sr.SchemaAt(RegimeCRAArticle14, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	assert.Equal(t, "ENISA-SRP-1.4", current.ID)
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
