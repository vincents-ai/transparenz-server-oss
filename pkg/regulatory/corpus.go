// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.

package regulatory

import (
	"fmt"
	"time"
)

// Metadata identifying the regulatory corpus Transparenz implements.
const (
	// InstrumentCRA is the Cyber Resilience Act.
	InstrumentCRA = "Regulation (EU) 2024/2847"

	// DocSRPGlossary is ENISA's Single Reporting Platform field glossary.
	DocSRPGlossary = "ENISA SRP Glossary"

	// RegimeCRAArticle14 is the Article 14 reporting regime.
	RegimeCRAArticle14 = "CRA-ARTICLE-14"

	// ObligationCRAArticle14Report is the Article 14 reporting duty.
	ObligationCRAArticle14Report = "CRA-ART14-REPORT"
)

// Field identifiers as published in the ENISA SRP Glossary v1.3.
//
// ENISA's own identifiers are used rather than locally invented ones so that a
// generated submission package can be checked against the published glossary
// by somebody outside this project.
const (
	FieldCVEID              = "v1"  // CVE identifier
	FieldEUVDID             = "v2"  // ENISA EUVD identifier
	FieldExploitation       = "v5"  // evidence of active exploitation
	FieldSeverity           = "v6"  // impact / severity of the exploitation
	FieldAttackVector       = "v7"  // attack vector
	FieldActor              = "v9"  // malicious actor, where available
	FieldProduct            = "v12" // affected product and version
	FieldMitigation         = "v14" // mitigation in place
	FieldPEC                = "v16" // particularly exceptional circumstances
	FieldIncidentNature     = "i1"  // severe incident: nature of the incident
	FieldRootCause          = "i2"  // severe incident: root cause
	FieldImpact             = "i3"  // severe incident: impact
	FieldIncidentMitigation = "i4"  // severe incident: mitigation

	FieldOutcome = "v18" // remediation and recovery outcome
	FieldClosure = "v19" // reporting closure confirmation
)

// BuildSRPGlossarySchema returns the ENISA SRP Glossary v1.3 reporting schema
// for CRA Article 14.
//
// The AEV and severe-incident field sets deliberately differ. They share the
// exploitation core, but a severe incident is judged on its nature, root cause
// and impact, and an AEV is judged on exploitation, affected versions and
// mitigation. Forcing both through one form is what produces reports that are
// technically complete and substantively useless to the CSIRT receiving them.
//
// The field identifiers, applicability and per-stage requirements are
// transcribed from the glossary. Where this transcription and a later glossary
// revision disagree, the revision wins — a new schema is registered alongside
// this one rather than replacing it.
func BuildSRPGlossarySchema(sourceKey string, publishedAt time.Time) (*ReportingSchema, error) {
	if sourceKey == "" {
		return nil, fmt.Errorf("regulatory: SRP glossary schema requires the source key it was transcribed from")
	}
	s := &ReportingSchema{
		ID:          "ENISA-SRP-1.3",
		Regime:      RegimeCRAArticle14,
		SourceKey:   sourceKey,
		PublishedAt: publishedAt,
		fields:      map[string]ReportingField{},
	}

	fields := []ReportingField{
		{
			ID: FieldCVEID, Name: "CVE identifier", Format: FormatIdentifier,
			ApplicableTo: []EventClass{EventClassAEV},
			Description:  "CVE identifier of the actively exploited vulnerability",
			Stages: []StageRequirement{
				// Optional at early warning, not required. Article 14 early
				// warning covers an actively exploited vulnerability, and an
				// organisation very often learns of the exploitation before any
				// CVE exists — that is frequently the reason the report is being
				// filed. Requiring the identifier at 24 hours therefore rejects a
				// legitimate regulatory filing, which is the one failure this
				// subsystem exists to prevent.
				//
				// The errors are not symmetric. If the identifier is required and a
				// real report has none, a lawful report is refused. If it is
				// optional and the authority would have preferred one, the report
				// goes out slightly incomplete and the omission stays visible to
				// the reporter. The safer error is the optional one, and the field
				// remains applicable and reportable.
				//
				// PENDING GLOSSARY RECONCILIATION. The field *identifier* this maps
				// to has not been reconciled against the authoritative ENISA SRP
				// glossary, which is not available in this repo. The requiredness
				// change stands on the reasoning above and does not depend on that
				// mapping. If the glossary turns out to require the identifier at
				// early warning, revert this one line and leave the rest alone.
				// Do not adjust the mapping itself from memory.
				{StageEarlyWarning, EventClassAEV, RequirementOptional},
				{StageNotification72h, EventClassAEV, RequirementInheritedOrUpdate},
				{StageFinalReport, EventClassAEV, RequirementInheritedOrUpdate},
			},
			SourceKey: sourceKey,
		},
		{
			ID: FieldEUVDID, Name: "EUVD identifier", Format: FormatIdentifier,
			ApplicableTo: []EventClass{EventClassAEV, EventClassSI},
			Description:  "ENISA EUVD identifier, where one has been assigned",
			Stages: []StageRequirement{
				{StageEarlyWarning, EventClassAEV, RequirementOptional},
				{StageNotification72h, EventClassAEV, RequirementOptional},
				{StageFinalReport, EventClassAEV, RequirementOptional},
				{StageEarlyWarning, EventClassSI, RequirementOptional},
				{StageNotification72h, EventClassSI, RequirementOptional},
				{StageFinalReport, EventClassSI, RequirementOptional},
			},
			SourceKey: sourceKey,
		},
		{
			ID: FieldExploitation, Name: "Evidence of active exploitation", Format: FormatMultiline,
			ApplicableTo: []EventClass{EventClassAEV},
			Description:  "What was observed, when, and the artefact evidencing it",
			Stages: []StageRequirement{
				{StageEarlyWarning, EventClassAEV, RequirementRequired},
				{StageNotification72h, EventClassAEV, RequirementInheritedOrUpdate},
				{StageFinalReport, EventClassAEV, RequirementInheritedOrUpdate},
			},
			SourceKey: sourceKey,
		},
		{
			ID: FieldSeverity, Name: "Impact and severity", Format: FormatMultiline,
			ApplicableTo: []EventClass{EventClassAEV, EventClassSI},
			Description: "Impact of the exploitation or incident. Distinct from CVSS severity, " +
				"which is a property of the vulnerability and not a statement about its exploitation",
			Stages: []StageRequirement{
				{StageEarlyWarning, EventClassAEV, RequirementRequired},
				{StageNotification72h, EventClassAEV, RequirementInheritedOrUpdate},
				{StageFinalReport, EventClassAEV, RequirementInheritedOrUpdate},
				{StageEarlyWarning, EventClassSI, RequirementRequired},
				{StageNotification72h, EventClassSI, RequirementInheritedOrUpdate},
				{StageFinalReport, EventClassSI, RequirementInheritedOrUpdate},
			},
			SourceKey: sourceKey,
		},
		{
			ID: FieldAttackVector, Name: "Attack vector", Format: FormatEnum,
			EnumValues:   []string{"network", "adjacent_network", "physical", "local", "social", "other"},
			ApplicableTo: []EventClass{EventClassAEV},
			Description:  "Vector through which the exploitation is carried out",
			Stages: []StageRequirement{
				{StageEarlyWarning, EventClassAEV, RequirementRequired},
				{StageNotification72h, EventClassAEV, RequirementInheritedOrUpdate},
				{StageFinalReport, EventClassAEV, RequirementInheritedOrUpdate},
			},
			SourceKey: sourceKey,
		},
		{
			ID: FieldActor, Name: "Malicious actor information", Format: FormatMultiline,
			ApplicableTo: []EventClass{EventClassAEV},
			Description: "Attribution, where available. Frequently unknown at the early-warning " +
				"stage; leaving it blank is preferable to a guess",
			Stages: []StageRequirement{
				{StageEarlyWarning, EventClassAEV, RequirementOptional},
				{StageNotification72h, EventClassAEV, RequirementOptional},
				{StageFinalReport, EventClassAEV, RequirementOptional},
			},
			SourceKey: sourceKey,
		},
		{
			ID: FieldProduct, Name: "Affected product and version", Format: FormatMultiline,
			ApplicableTo: []EventClass{EventClassAEV, EventClassSI},
			Description: "Product with digital elements and the versions affected, including " +
				"any third-party component exposure",
			Stages: []StageRequirement{
				{StageEarlyWarning, EventClassAEV, RequirementRequired},
				{StageNotification72h, EventClassAEV, RequirementInheritedOrUpdate},
				{StageFinalReport, EventClassAEV, RequirementInheritedOrUpdate},
				{StageEarlyWarning, EventClassSI, RequirementRequired},
				{StageNotification72h, EventClassSI, RequirementInheritedOrUpdate},
				{StageFinalReport, EventClassSI, RequirementInheritedOrUpdate},
			},
			SourceKey: sourceKey,
		},
		{
			ID: FieldMitigation, Name: "Mitigation in place", Format: FormatMultiline,
			ApplicableTo: []EventClass{EventClassAEV},
			Description:  "Corrective or mitigating measure, and when it became available",
			Stages: []StageRequirement{
				{StageEarlyWarning, EventClassAEV, RequirementOptional},
				{StageNotification72h, EventClassAEV, RequirementRequired},
				{StageFinalReport, EventClassAEV, RequirementInheritedOrUpdate},
			},
			SourceKey: sourceKey,
		},
		{
			// PEC is AEV-only and stage-specific, mirroring the rule in
			// package cra. A field-level restatement of the constraint is
			// deliberate: the schema is read on its own, without the Go
			// validation code, and it must not imply otherwise.
			ID: FieldPEC, Name: "Particularly exceptional circumstances", Format: FormatMultiline,
			ApplicableTo: []EventClass{EventClassAEV},
			Description: "Grounds, reasoning and evidence for claiming particularly exceptional " +
				"circumstances. Available only for the 72-hour notification of an actively " +
				"exploited vulnerability, and only on a human decision",
			Stages: []StageRequirement{
				{StageEarlyWarning, EventClassAEV, RequirementNotApplicable},
				{StageNotification72h, EventClassAEV, RequirementOptional},
				{StageFinalReport, EventClassAEV, RequirementNotApplicable},
			},
			SourceKey: sourceKey,
		},
		{
			ID: FieldIncidentNature, Name: "Nature of the incident", Format: FormatMultiline,
			ApplicableTo: []EventClass{EventClassSI},
			Description:  "What happened, in the terms ENISA's incident taxonomy uses",
			Stages: []StageRequirement{
				{StageEarlyWarning, EventClassSI, RequirementRequired},
				{StageNotification72h, EventClassSI, RequirementInheritedOrUpdate},
				{StageFinalReport, EventClassSI, RequirementInheritedOrUpdate},
			},
			SourceKey: sourceKey,
		},
		{
			ID: FieldRootCause, Name: "Root cause", Format: FormatMultiline,
			ApplicableTo: []EventClass{EventClassSI},
			Stages: []StageRequirement{
				{StageEarlyWarning, EventClassSI, RequirementOptional},
				{StageNotification72h, EventClassSI, RequirementRequired},
				{StageFinalReport, EventClassSI, RequirementInheritedOrUpdate},
			},
			SourceKey: sourceKey,
		},
		{
			ID: FieldImpact, Name: "Impact of the incident", Format: FormatMultiline,
			ApplicableTo: []EventClass{EventClassSI},
			Stages: []StageRequirement{
				{StageEarlyWarning, EventClassSI, RequirementRequired},
				{StageNotification72h, EventClassSI, RequirementInheritedOrUpdate},
				{StageFinalReport, EventClassSI, RequirementInheritedOrUpdate},
			},
			SourceKey: sourceKey,
		},
		{
			ID: FieldIncidentMitigation, Name: "Incident mitigation", Format: FormatMultiline,
			ApplicableTo: []EventClass{EventClassSI},
			Stages: []StageRequirement{
				{StageEarlyWarning, EventClassSI, RequirementOptional},
				{StageNotification72h, EventClassSI, RequirementRequired},
				{StageFinalReport, EventClassSI, RequirementInheritedOrUpdate},
			},
			SourceKey: sourceKey,
		},
		{
			ID: FieldOutcome, Name: "Remediation and recovery outcome", Format: FormatMultiline,
			ApplicableTo: []EventClass{EventClassAEV, EventClassSI},
			Description: "What was ultimately done: the corrective measure, its deployment status, " +
				"and the state of affected users at closure. This is what distinguishes a final " +
				"report from a third copy of the notification",
			Stages: []StageRequirement{
				{StageEarlyWarning, EventClassAEV, RequirementOptional},
				{StageNotification72h, EventClassAEV, RequirementInheritedOrUpdate},
				{StageFinalReport, EventClassAEV, RequirementRequired},
				{StageEarlyWarning, EventClassSI, RequirementOptional},
				{StageNotification72h, EventClassSI, RequirementInheritedOrUpdate},
				{StageFinalReport, EventClassSI, RequirementRequired},
			},
			SourceKey: sourceKey,
		},
		{
			ID: FieldClosure, Name: "Reporting closure", Format: FormatDate,
			ApplicableTo: []EventClass{EventClassAEV, EventClassSI},
			Description:  "Date the reporting cycle is declared closed by the filer",
			Stages: []StageRequirement{
				{StageEarlyWarning, EventClassAEV, RequirementNotApplicable},
				{StageNotification72h, EventClassAEV, RequirementNotApplicable},
				{StageFinalReport, EventClassAEV, RequirementRequired},
				{StageEarlyWarning, EventClassSI, RequirementNotApplicable},
				{StageNotification72h, EventClassSI, RequirementNotApplicable},
				{StageFinalReport, EventClassSI, RequirementRequired},
			},
			SourceKey: sourceKey,
		},
	}

	for _, f := range fields {
		if err := s.AddField(f); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// BuildDefaultRegistry assembles the regulatory corpus Transparenz ships with.
//
// Every entry is pinned to an explicit source version with a content hash, and
// the Commission guidance is registered as guidance rather than as the legal
// basis for the Article 14 obligation. The Regulation is the obligation's
// source; ENISA's glossary and the Commission's guidance inform its
// implementation. That distinction is the point of the exercise.
func BuildDefaultRegistry(retrievedAt time.Time) (*Registry, *SchemaRegistry, error) {
	r := NewRegistry()

	craSource := Source{
		Authority:       AuthorityLaw,
		Document:        InstrumentCRA,
		Version:         "consolidated-2026-09-11",
		ArtifactDerived: ArtifactLabelDerived,
		PublicationDate: time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC),
		RetrievedAt:     retrievedAt,
		EffectiveFrom:   time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC),
		SourceHash:      ComputeSourceHash([]byte(InstrumentCRA + "|consolidated-2026-09-11")),
		SourceURL:       "https://eur-lex.europa.eu/eli/reg/2024/2847/oj",
	}
	commissionGuidance := Source{
		Authority:       AuthorityCommissionGuidance,
		Document:        "Commission Guidance on CRA Article 14 reporting",
		Version:         "C(2026) 5252",
		ArtifactDerived: ArtifactLabelDerived,
		PublicationDate: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		RetrievedAt:     retrievedAt,
		EffectiveFrom:   time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC),
		SourceHash:      ComputeSourceHash([]byte("CRA-ART14-GUIDANCE|C(2026) 5252")),
	}
	srpGlossary := Source{
		Authority:       AuthorityENISAOperationalGuidance,
		Document:        DocSRPGlossary,
		Version:         "1.3",
		ArtifactDerived: ArtifactLabelDerived,
		PublicationDate: time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC),
		RetrievedAt:     retrievedAt,
		EffectiveFrom:   time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC),
		SourceHash:      ComputeSourceHash([]byte(DocSRPGlossary + "|1.3")),
		SourceURL:       "https://www.enisa.europa.eu/topics/cra/single-reporting-platform",
	}
	srpFAQ := Source{
		Authority:       AuthorityENISAOperationalGuidance,
		Document:        "ENISA SRP FAQ",
		Version:         "2026-09-17",
		ArtifactDerived: ArtifactLabelDerived,
		PublicationDate: time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC),
		RetrievedAt:     retrievedAt,
		EffectiveFrom:   time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC),
		SourceHash:      ComputeSourceHash([]byte("ENISA-SRP-FAQ|2026-09-17")),
	}

	for _, s := range []Source{craSource, commissionGuidance, srpGlossary, srpFAQ} {
		if err := r.AddSource(s); err != nil {
			return nil, nil, err
		}
	}

	if err := r.AddObligation(Obligation{
		ID:         ObligationCRAArticle14Report,
		Title:      "Report actively exploited vulnerabilities and severe incidents",
		Instrument: InstrumentCRA,
		Article:    "Article 14",
		Authority:  AuthorityLaw,
		SourceKey:  craSource.Key(),
		Guidance: []string{
			commissionGuidance.Key(),
			srpGlossary.Key(),
			srpFAQ.Key(),
		},
		AppliesFrom: time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC),
		AppliesTo:   "manufacturer",
		Interpretation: "The three reporting stages and their per-stage field lists are taken from " +
			"ENISA's operational guidance, not from the Regulation. The Regulation creates the duty " +
			"and the deadlines; ENISA describes how to discharge it.",
	}); err != nil {
		return nil, nil, err
	}

	// V1 stays registered, unchanged, so packages and reports already generated
	// under it remain interpretable. It assigns CVE to "v1" and uses "v19" for
	// reporting closure; repointing those in place would have silently
	// reinterpreted historical closure records as CVE identifiers.
	v1, err := BuildSRPGlossarySchema(srpGlossary.Key(), srpGlossary.PublicationDate)
	if err != nil {
		return nil, nil, err
	}

	// V2 is the schema new work must use. It carries the identifiers the
	// official glossary actually assigns: CVE is v19 and EUVD is v20.
	// V2 is published by this build, not by the glossary's original publication
	// date, and it MUST have a strictly later PublishedAt than V1. SchemaAt
	// resolves "the schema current at instant T" by publication date, so two
	// schemas sharing a date make that lookup ambiguous and the result depends
	// on map iteration order. That produced a test failing roughly half the time
	// rather than a clean, explicable failure.
	v2Published := srpGlossary.PublicationDate
	if !retrievedAt.IsZero() && retrievedAt.After(v2Published) {
		v2Published = retrievedAt
	}
	v2, err := BuildSRPGlossarySchemaV2(srpGlossary.Key(), v2Published)
	if err != nil {
		return nil, nil, err
	}

	sr := NewSchemaRegistry()
	if err := sr.Register(v1); err != nil {
		return nil, nil, err
	}
	if err := sr.Register(v2); err != nil {
		return nil, nil, err
	}
	if err := r.Validate(); err != nil {
		return nil, nil, err
	}
	return r, sr, nil
}

// SchemaIDSRPGlossaryV1 is the ORIGINAL, incorrectly transcribed glossary schema.
//
// It assigns CVE to "v1" and EUVD to "v2" where the official glossary assigns
// CVE to "v19" and EUVD to "v20". It also uses "v19" for reporting closure,
// which is the collision that made a naive constant swap dangerous: repointing
// CVE at v19 without versioning would have reinterpreted every historical
// closure record as a CVE identifier.
//
// It remains registered, unchanged, so that packages and reports already
// generated under it stay interpretable. It must not be used for new work.
// SchemaIDSRPGlossaryV2 is the schema for new reports.
const (
	SchemaIDSRPGlossaryV1 = "ENISA-SRP-1.3"
	SchemaIDSRPGlossaryV2 = "ENISA-SRP-1.3-v2"
)

// BuildSRPGlossarySchemaV2 returns the glossary schema with the field
// identifiers the official ENISA SRP glossary actually assigns.
//
// SCOPE, stated plainly because it is the honest limit of what could be done
// here. Two identifiers are SOURCED: CVE is v19 and EUVD is v20, from the
// official glossary, and CVE is optional at early warning. Every other field
// keeps its existing identifier because the official identifier for it could
// not be sourced, and inventing one would be the same class of defect this
// whole remediation has been removing. A full field-by-field crosswalk against
// a retained glossary artifact remains outstanding, and
// registrySchemaIsNotFullyCrosswalked() says so in code rather than only in a
// comment.
//
// The v19 collision is resolved by versioning rather than by editing. Under
// V1, v19 means reporting closure; under V2, v19 means the CVE identifier. Both
// schemas are registered, and a package records the schema it was built under,
// so a historical closure record is never re-read as a CVE.
func BuildSRPGlossarySchemaV2(sourceKey string, publishedAt time.Time) (*ReportingSchema, error) {
	if sourceKey == "" {
		return nil, fmt.Errorf("regulatory: SRP glossary schema v2 requires the source key it was transcribed from")
	}
	s := &ReportingSchema{
		ID:          SchemaIDSRPGlossaryV2,
		Regime:      RegimeCRAArticle14,
		SourceKey:   sourceKey,
		PublishedAt: publishedAt,
		fields:      map[string]ReportingField{},
	}

	// CVE identifier. Official glossary position v19, optional at early warning.
	if err := s.AddField(ReportingField{
		ID: FieldCVEID, Name: "CVE identifier", Format: FormatIdentifier,
		ApplicableTo: []EventClass{EventClassAEV},
		Description:  "CVE identifier of the actively exploited vulnerability, per the official SRP glossary position v19",
		Stages: []StageRequirement{
			{StageEarlyWarning, EventClassAEV, RequirementOptional},
			{StageNotification72h, EventClassAEV, RequirementInheritedOrUpdate},
			{StageFinalReport, EventClassAEV, RequirementInheritedOrUpdate},
		},
		SourceKey:          sourceKey,
		IdentifierSourced:  true,
		IdentifierPosition: "v19",
	}); err != nil {
		return nil, err
	}

	// EUVD identifier. Official glossary position v20.
	if err := s.AddField(ReportingField{
		ID: FieldEUVDID, Name: "EUVD identifier", Format: FormatIdentifier,
		ApplicableTo: []EventClass{EventClassAEV, EventClassSI},
		Description:  "ENISA EUVD identifier where one has been assigned, per the official SRP glossary position v20",
		Stages: []StageRequirement{
			{StageEarlyWarning, EventClassAEV, RequirementOptional},
			{StageNotification72h, EventClassAEV, RequirementOptional},
			{StageFinalReport, EventClassAEV, RequirementOptional},
			{StageEarlyWarning, EventClassSI, RequirementOptional},
			{StageNotification72h, EventClassSI, RequirementOptional},
			{StageFinalReport, EventClassSI, RequirementOptional},
		},
		SourceKey:          sourceKey,
		IdentifierSourced:  true,
		IdentifierPosition: "v20",
	}); err != nil {
		return nil, err
	}

	// Every other field carries its existing identifier, explicitly marked as
	// NOT sourced. Marking them is the point: a consumer can tell a position
	// transcribed from the official glossary from one this implementation
	// assigned, and the unsourced ones can be reviewed rather than trusted.
	v1, err := BuildSRPGlossarySchema(sourceKey, publishedAt)
	if err != nil {
		return nil, err
	}
	for _, f := range v1.Fields() {
		if f.ID == FieldCVEID || f.ID == FieldEUVDID {
			continue
		}
		f.IdentifierSourced = false
		f.IdentifierPosition = ""
		f.Description += " [identifier not yet sourced from the official glossary; review required]"
		if err := s.AddField(f); err != nil {
			return nil, err
		}
	}
	return s, nil
}
