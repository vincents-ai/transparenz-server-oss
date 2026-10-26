// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.

package regulatory

import (
	_ "embed"
	"fmt"
	"time"
)

// SchemaIDSRPGlossaryV16 is the reporting schema transcribed from ENISA SRP
// Glossary v1.6 (last update 21 October 2026).
//
// Unlike ENISA-SRP-1.3 and ENISA-SRP-1.3-v2, this schema's id states the
// glossary version it was actually transcribed from. That is deliberate: the two
// earlier schemas carry ids that describe a derivation, and reusing them for a
// different field list would make a package's schema id stop identifying the
// field list the package was built against.
const SchemaIDSRPGlossaryV16 = "ENISA-SRP-1.6"

// Field identifiers for the v1.6 glossary, transcribed verbatim.
//
// The identifiers are ENISA's own — "1" through "18", "7a", "v19" through
// "v30", "v26a", "i31" through "i39", "40", "41" — so that a package built
// against this schema can be checked against the published glossary by somebody
// who has never seen this codebase.
//
// They are declared as a separate set from the older Field* constants rather
// than replacing them. The older constants are NOT interchangeable with these:
// under the earlier transcription FieldCVEID is "v1", and "v1" in v1.6 is the
// notification type. Two constants holding different meanings for one string is
// how a field mapping silently becomes wrong, so the v1.6 identifiers are given
// names of their own and the earlier ones left describing the earlier schemas.
const (
	// Common fields.

	FieldV16NotificationType = "1"
	FieldV16Title            = "2"
	FieldV16Summary          = "3"
	FieldV16ManufacturerName = "4"
	FieldV16MemberStates     = "5"
	FieldV16ProductName      = "6"
	FieldV16ProductVersion   = "7"
	FieldV16AdditionalInfo   = "7a"
	FieldV16ProductType      = "8"
	FieldV16ProductClass     = "9"
	FieldV16ProductCategory  = "10"
	FieldV16EndOfSupport     = "11"
	FieldV16ComponentName    = "12"
	FieldV16MitigationSoon   = "13"
	FieldV16UserAction       = "14"
	FieldV16Sensitivity      = "15"
	FieldV16MeasuresTaken    = "16"
	FieldV16MeasuresForUsers = "17"
	FieldV16AttackVector     = "18"

	// Actively exploited vulnerability.

	FieldV16CVEID          = "v19"
	FieldV16EUVDID         = "v20"
	FieldV16GeneralInfo    = "v21"
	FieldV16MeasureDate    = "v22"
	FieldV16UpdateDetails  = "v23"
	FieldV16SeverityDesc   = "v24"
	FieldV16ImpactDesc     = "v25"
	FieldV16AEVAwareness   = "v26"
	FieldV16AEVOccurred    = "v26a"
	FieldV16Actor          = "v27"
	FieldV16PEC            = "v28"
	FieldV16PECDelayReason = "v29"
	FieldV16FurtherInfo    = "v30"

	// Severe incident.

	FieldV16IncidentSuspected  = "i31"
	FieldV16IncidentNature     = "i32"
	FieldV16IncidentMeasures   = "i33"
	FieldV16IncidentSeverity   = "i34"
	FieldV16IncidentImpact     = "i35"
	FieldV16IncidentRootCause  = "i36"
	FieldV16IncidentAwareness  = "i37"
	FieldV16IncidentOccurred   = "i38"
	FieldV16IncidentAssessment = "i39"

	// Case-management notes.

	FieldV16ARNote    = "40"
	FieldV16CSIRTNote = "41"
)

// SRPTimestampLayout is the representation the glossary prints for every
// date-time field, e.g. "2026-08-24 09:15 UTC".
//
// A package value in this form can be copied into the Single Reporting Platform
// unchanged. RFC3339 is also accepted on validation, but a human filing a report
// should never have to reformat a value this product produced.
const SRPTimestampLayout = "2006-01-02 15:04 MST"

// SRPTimestamp renders an instant the way the SRP glossary does, in UTC.
func SRPTimestamp(t time.Time) string {
	return t.UTC().Format(SRPTimestampLayout)
}

// ParseSRPTimestamp parses a glossary-formatted timestamp back to an instant.
// It exists so a test can prove that the value written into a package denotes
// the same instant the deadline was computed from, rather than merely looking
// like it.
func ParseSRPTimestamp(s string) (time.Time, error) {
	t, err := time.Parse(SRPTimestampLayout, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("regulatory: %q is not an SRP timestamp: %w", s, err)
	}
	return t.UTC(), nil
}

// AwarenessFieldFor returns the v1.6 field a report's awareness timestamp is
// filed in, per event class.
//
// The awareness instant is the anchor every Article 14 deadline is computed
// from, and v1.6 makes both fields mandatory at early warning. Keeping the
// mapping in one place means the value that starts the clock and the value that
// is filed cannot drift apart by being derived in two different call sites.
func AwarenessFieldFor(class EventClass) (string, bool) {
	switch class {
	case EventClassAEV:
		return FieldV16AEVAwareness, true
	case EventClassSI:
		return FieldV16IncidentAwareness, true
	default:
		return "", false
	}
}

// srp16Field is one row of the v1.6 field matrix: the field, and its
// requirement at each of the three stages, applied to every event class it
// covers.
//
// It is expressed as a row rather than as a ReportingField literal because the
// v1.6 glossary publishes exactly one requirement triple per field, and writing
// the triple once per row is what keeps this table comparable line by line with
// the published document.
type srp16Field struct {
	id      string
	name    string
	desc    string
	format  FieldFormat
	enum    []string
	maxLen  int
	applies []EventClass
	// authorityAuthored marks a field the CSIRT writes, not the manufacturer.
	authorityAuthored bool
	ew                Requirement
	n72               Requirement
	fr                Requirement
}

// bothClasses is the event-class set for a field the glossary marks "Both".
var bothClasses = []EventClass{EventClassAEV, EventClassSI}

// aevOnly is the event-class set for an AEV-specific field.
var aevOnly = []EventClass{EventClassAEV}

// siOnly is the event-class set for a severe-incident-specific field.
var siOnly = []EventClass{EventClassSI}

// srp16Matrix is ENISA SRP Glossary v1.6, row by row.
//
// Requirement vocabulary: Required and Optional are the glossary's own words.
// Mandatory is also the glossary's word and is recorded as RequirementRequired,
// because a field that must be present is required and inventing a fifth
// category would make the schema disagree with the document it cites.
// "Copied from previous step by default, or updated" and "Required if such
// information is available" are recorded as RequirementInheritedOrUpdate: the
// value must carry forward when it exists, and its absence is not an error.
//
// Every row is a sourced identifier: IdentifierPosition is set from id, so a
// consumer cannot confuse a transcribed position with one this codebase chose.
var srp16Matrix = []srp16Field{
	// --- Common fields -----------------------------------------------------
	{
		id: FieldV16NotificationType, name: "Notification type",
		desc:   "Whether the notification concerns an actively exploited vulnerability or a severe incident.",
		format: FormatEnum, enum: []string{"Vulnerability", "Incident"},
		applies: bothClasses,
		ew:      RequirementRequired, n72: RequirementNotApplicable, fr: RequirementNotApplicable,
	},
	{
		id: FieldV16Title, name: "Title",
		desc: "Short human-readable name for the notification, identifying the product and the issue " +
			"without unnecessary confidential detail.",
		format: FormatText, maxLen: 255,
		applies: bothClasses,
		ew:      RequirementRequired, n72: RequirementNotApplicable, fr: RequirementNotApplicable,
	},
	{
		id: FieldV16Summary, name: "Summary",
		desc: "Concise overview of the facts, the affected product and the issue being notified, " +
			"limited to what is known at the reporting stage.",
		format: FormatMultiline, maxLen: 4000,
		applies: bothClasses,
		ew:      RequirementRequired, n72: RequirementNotApplicable, fr: RequirementNotApplicable,
	},
	{
		id: FieldV16ManufacturerName, name: "Manufacturer name",
		desc: "Name of the manufacturer, populated by the platform from the registration and read-only " +
			"during filing. A package supplies it for confirmation; the platform value prevails.",
		format:  FormatText,
		applies: bothClasses,
		ew:      RequirementRequired, n72: RequirementNotApplicable, fr: RequirementNotApplicable,
	},
	{
		id: FieldV16MemberStates, name: "Member States where product available",
		desc: "Member States in which the affected product is known to have been made available; " +
			"determines the concerned CSIRTs. The coordinating CSIRT is pre-filled by the platform.",
		format:  FormatList,
		applies: bothClasses,
		ew:      RequirementRequired, n72: RequirementNotApplicable, fr: RequirementNotApplicable,
	},
	{
		id: FieldV16ProductName, name: "Product Name",
		desc:   "Official commercial or technical name of the affected product with digital elements.",
		format: FormatText, maxLen: 255,
		applies: bothClasses,
		ew:      RequirementRequired, n72: RequirementNotApplicable, fr: RequirementNotApplicable,
	},
	{
		id: FieldV16ProductVersion, name: "Product Version",
		desc: "Affected versions, releases, builds or firmware revisions, with ranges stated explicitly " +
			"where several versions are affected.",
		format: FormatText, maxLen: 255,
		applies: bothClasses,
		ew:      RequirementRequired, n72: RequirementNotApplicable, fr: RequirementNotApplicable,
	},
	{
		id: FieldV16AdditionalInfo, name: "Additional Information",
		desc: "Extra details about the manufacturer that the standard fields do not cover and that help " +
			"the coordinating CSIRT identify the entity.",
		format: FormatText, maxLen: 255,
		applies: bothClasses,
		ew:      RequirementOptional, n72: RequirementNotApplicable, fr: RequirementNotApplicable,
	},
	{
		id: FieldV16ProductType, name: "Product Type",
		desc: "CRA regulatory category of the product. Important or Critical only where the product " +
			"falls within the relevant Annex III or IV category.",
		format: FormatEnum, enum: []string{"Default", "Important", "Critical"},
		applies: bothClasses,
		ew:      RequirementOptional, n72: RequirementNotApplicable, fr: RequirementNotApplicable,
	},
	{
		id: FieldV16ProductClass, name: "Product class",
		desc: "For an important product, the Class I or Class II category used for conformity-assessment " +
			"treatment. Empty when the product is not an important product.",
		format:  FormatText,
		applies: bothClasses,
		ew:      RequirementOptional, n72: RequirementNotApplicable, fr: RequirementNotApplicable,
	},
	{
		id: FieldV16ProductCategory, name: "Product category",
		desc: "The applicable CRA product category from the Annex III or IV category list, selected by " +
			"core functionality rather than commercial name.",
		format:  FormatText,
		applies: bothClasses,
		ew:      RequirementOptional, n72: RequirementNotApplicable, fr: RequirementNotApplicable,
	},
	{
		id: FieldV16EndOfSupport, name: "End of the support indicator",
		desc:   "Whether the product has reached the end of its support period.",
		format: FormatEnum, enum: []string{"Yes", "No"},
		applies: bothClasses,
		ew:      RequirementOptional, n72: RequirementNotApplicable, fr: RequirementNotApplicable,
	},
	{
		id: FieldV16ComponentName, name: "Component name",
		desc: "Name, and where known the version, of the software or hardware component in which the " +
			"vulnerability or incident is located or observed.",
		format: FormatText, maxLen: 255,
		applies: bothClasses,
		ew:      RequirementOptional, n72: RequirementNotApplicable, fr: RequirementNotApplicable,
	},
	{
		id: FieldV16MitigationSoon, name: "Mitigating measure expected shortly",
		desc: "Whether an effective risk-mitigation measure is expected shortly and the expectation is " +
			"supported by a remediation plan.",
		format: FormatEnum, enum: []string{"Yes", "No"},
		applies: bothClasses,
		ew:      RequirementOptional, n72: RequirementNotApplicable, fr: RequirementNotApplicable,
	},
	{
		id: FieldV16UserAction, name: "User Action able to reduce impact",
		desc: "Practical action users can take to prevent, reduce or contain the impact, with any " +
			"limitation or prerequisite stated.",
		format: FormatMultiline, maxLen: 4000,
		applies: bothClasses,
		ew:      RequirementOptional, n72: RequirementNotApplicable, fr: RequirementNotApplicable,
	},
	{
		id: FieldV16Sensitivity, name: "Considered sensitivity of information",
		desc: "Why submitted information requires restricted handling: the sensitive element and the " +
			"consequence of premature or wider disclosure.",
		format: FormatText, maxLen: 255,
		applies: bothClasses,
		ew:      RequirementOptional, n72: RequirementOptional, fr: RequirementNotApplicable,
	},
	{
		id: FieldV16MeasuresTaken, name: "Corrective or mitigating measures taken",
		desc: "Actions already implemented to correct the issue or reduce its risk or impact, with dates " +
			"where useful.",
		format: FormatMultiline, maxLen: 2000,
		applies: bothClasses,
		ew:      RequirementOptional, n72: RequirementOptional, fr: RequirementRequired,
	},
	{
		id: FieldV16MeasuresForUsers, name: "Corrective or mitigating measures that users can take",
		desc: "Step-oriented guidance users can apply: the effective fix first, then temporary " +
			"workarounds and their operational impact.",
		format: FormatMultiline, maxLen: 4000,
		applies: bothClasses,
		ew:      RequirementOptional, n72: RequirementOptional, fr: RequirementRequired,
	},
	{
		id: FieldV16AttackVector, name: "Attack vector",
		desc: "The path or means by which exploitation or compromise can occur: the interface, access " +
			"path, protocol or user interaction. Not applicable at early warning or at the final report.",
		format: FormatText, maxLen: 255,
		applies: bothClasses,
		ew:      RequirementNotApplicable, n72: RequirementOptional, fr: RequirementNotApplicable,
	},

	// --- Actively exploited vulnerability ----------------------------------
	{
		id: FieldV16CVEID, name: "CVE ID",
		desc: "CVE identifier assigned by the competent CNA, copied exactly. Empty where no identifier " +
			"has been assigned. Available only at early warning.",
		format: FormatIdentifier, maxLen: 255,
		applies: aevOnly,
		ew:      RequirementOptional, n72: RequirementNotApplicable, fr: RequirementNotApplicable,
	},
	{
		id: FieldV16EUVDID, name: "EUVD ID",
		desc: "Identifier of the vulnerability record in the European Vulnerability Database, where " +
			"ENISA has assigned one. Available only at early warning.",
		format: FormatIdentifier, maxLen: 255,
		applies: aevOnly,
		ew:      RequirementOptional, n72: RequirementNotApplicable, fr: RequirementNotApplicable,
	},
	{
		id: FieldV16GeneralInfo, name: "General information",
		desc: "High-level description of the vulnerability and, where known, how the exploit works, " +
			"without unverified attribution.",
		format: FormatMultiline, maxLen: 4000,
		applies: aevOnly,
		ew:      RequirementOptional, n72: RequirementRequired, fr: RequirementNotApplicable,
	},
	{
		id: FieldV16MeasureDate, name: "Date when corrective or mitigating measure has been available",
		desc: "Date and time the mitigating measure became available. The glossary makes this " +
			"unavailable until field 17 (measures users can take) is complete, and requires it at the " +
			"final report.",
		format:  FormatDateTime,
		applies: aevOnly,
		ew:      RequirementOptional, n72: RequirementOptional, fr: RequirementRequired,
	},
	{
		id: FieldV16UpdateDetails, name: "Details about the security update or corrective measure available",
		desc:   "Information on the available corrective measures and security updates.",
		format: FormatMultiline, maxLen: 2000,
		applies: aevOnly,
		ew:      RequirementOptional, n72: RequirementOptional, fr: RequirementRequired,
	},
	{
		id: FieldV16SeverityDesc, name: "Description of the severity of the vulnerability",
		desc: "Complete technical description including the assessed severity rating, the rationale for " +
			"it and the factors supporting it.",
		format: FormatMultiline, maxLen: 4000,
		applies: aevOnly,
		ew:      RequirementOptional, n72: RequirementOptional, fr: RequirementRequired,
	},
	{
		id: FieldV16ImpactDesc, name: "Description of the impact of the vulnerability",
		desc: "Complete description of the potential or actual impact: affected systems, components, " +
			"data, users or services.",
		format: FormatMultiline, maxLen: 4000,
		applies: aevOnly,
		ew:      RequirementOptional, n72: RequirementOptional, fr: RequirementRequired,
	},
	{
		id: FieldV16AEVAwareness, name: "Date and time when you become aware of the actively exploited vulnerability",
		desc: "When the manufacturer or another relevant party first detected the vulnerability. This is " +
			"the instant the Article 14 clock runs from, and v1.6 makes it mandatory at early warning. " +
			"An estimate must be identified as estimated.",
		format:  FormatDateTime,
		applies: aevOnly,
		ew:      RequirementRequired, n72: RequirementNotApplicable, fr: RequirementNotApplicable,
	},
	{
		id: FieldV16AEVOccurred, name: "Date and time when the actively exploited vulnerability occurred",
		desc:    "Known or estimated instant from which the vulnerability exists.",
		format:  FormatDateTime,
		applies: aevOnly,
		ew:      RequirementOptional, n72: RequirementInheritedOrUpdate, fr: RequirementNotApplicable,
	},
	{
		id: FieldV16Actor, name: "Malicious actor that has exploited or is exploiting the vulnerability",
		desc: "Confirmed information about the actor, or the observed indicators with attribution stated " +
			"as unknown. Required at the final report where such information is available.",
		format: FormatText, maxLen: 100,
		applies: aevOnly,
		ew:      RequirementOptional, n72: RequirementOptional, fr: RequirementInheritedOrUpdate,
	},
	{
		id: FieldV16PEC, name: "Particularly Exceptional Circumstances (PEC)",
		desc: "The Article 16(2) third-subparagraph circumstances that justify withholding the full " +
			"72-hour notification from simultaneous access by ENISA, or delaying wider dissemination: " +
			"(a) exploitation confined to the coordinating CSIRT's Member State, (b) essential national " +
			"security or defence interests, (c) imminent high cybersecurity risk that cannot yet be " +
			"mitigated. Available only at the 72-hour stage.",
		format:  FormatList,
		applies: aevOnly,
		ew:      RequirementNotApplicable, n72: RequirementOptional, fr: RequirementNotApplicable,
	},
	{
		id: FieldV16PECDelayReason, name: "PEC Delay Reason",
		desc: "The selected legally specified circumstance, supported by specific facts, with the " +
			"requested dissemination delay.",
		format:  FormatText,
		applies: aevOnly,
		ew:      RequirementNotApplicable, n72: RequirementOptional, fr: RequirementNotApplicable,
	},
	{
		id: FieldV16FurtherInfo, name: "Please provide further information",
		desc:   "Anything helpful to the coordinating CSIRT in reaching its decision under PEC.",
		format: FormatText, maxLen: 800,
		applies: aevOnly,
		ew:      RequirementNotApplicable, n72: RequirementOptional, fr: RequirementNotApplicable,
	},

	// --- Severe incident ---------------------------------------------------
	{
		id: FieldV16IncidentSuspected, name: "Incident is suspected of unlawful or malicious acts",
		desc: "Whether the available evidence indicates intentional unlawful or malicious activity. " +
			"Free text: state Yes, No or Unknown and add supporting information where available.",
		format: FormatText, maxLen: 255,
		applies: siOnly,
		ew:      RequirementRequired, n72: RequirementInheritedOrUpdate, fr: RequirementNotApplicable,
	},
	{
		id: FieldV16IncidentNature, name: "General information about the nature of the incident",
		desc: "What happened, how the incident manifested, and the affected security properties or " +
			"functions, limited to confirmed facts available at the 72-hour stage.",
		format: FormatMultiline, maxLen: 4000,
		applies: siOnly,
		ew:      RequirementOptional, n72: RequirementRequired, fr: RequirementNotApplicable,
	},
	{
		id: FieldV16IncidentMeasures, name: "Applied and ongoing mitigation measures",
		desc:   "Actions taken and still ongoing to correct the issue or reduce its risk or impact.",
		format: FormatMultiline, maxLen: 4000,
		applies: siOnly,
		ew:      RequirementOptional, n72: RequirementOptional, fr: RequirementRequired,
	},
	{
		id: FieldV16IncidentSeverity, name: "Detailed description of the Severity of the incident",
		desc: "Sequence of events, affected products and functions, severity, scope, evidence, root " +
			"cause, response measures and recovery status.",
		format: FormatMultiline, maxLen: 4000,
		applies: siOnly,
		ew:      RequirementOptional, n72: RequirementOptional, fr: RequirementRequired,
	},
	{
		id: FieldV16IncidentImpact, name: "Detailed description of the Impact of the incident",
		desc:   "Impact on the product, data, functions, users or connected systems.",
		format: FormatMultiline, maxLen: 4000,
		applies: siOnly,
		ew:      RequirementOptional, n72: RequirementOptional, fr: RequirementRequired,
	},
	{
		id: FieldV16IncidentRootCause, name: "Type of Threat or root cause likely to have triggered the incident",
		desc: "Most likely threat category and root cause supported by the investigation, with a " +
			"preliminary conclusion marked as preliminary.",
		format: FormatText, maxLen: 255,
		applies: siOnly,
		ew:      RequirementOptional, n72: RequirementOptional, fr: RequirementRequired,
	},
	{
		id: FieldV16IncidentAwareness, name: "Date and time when you become aware of the incident",
		desc: "When the manufacturer or another relevant entity became aware of the incident. This is " +
			"the instant the Article 14 clock runs from, and v1.6 makes it mandatory at early warning. " +
			"v1.6 also renamed it: v1.4 called this field the time the incident was detected.",
		format:  FormatDateTime,
		applies: siOnly,
		ew:      RequirementRequired, n72: RequirementNotApplicable, fr: RequirementNotApplicable,
	},
	{
		id: FieldV16IncidentOccurred, name: "Date and time when the incident occurred",
		desc:    "Known or estimated instant at which the incident began or took place.",
		format:  FormatDateTime,
		applies: siOnly,
		ew:      RequirementOptional, n72: RequirementOptional, fr: RequirementNotApplicable,
	},
	{
		id: FieldV16IncidentAssessment, name: "Initial assessment of the incident",
		desc: "Preliminary analysis of severity, scope, affected security properties, products or users " +
			"and likely impact, distinguishing confirmed findings from open questions.",
		format: FormatMultiline, maxLen: 4000,
		applies: siOnly,
		ew:      RequirementOptional, n72: RequirementRequired, fr: RequirementNotApplicable,
	},

	// --- Case-management notes --------------------------------------------
	{
		id: FieldV16ARNote, name: "AR Note",
		desc: "Free-text note entered by the assigned representative to supplement the notification. " +
			"This is the only field the assigned representative authors, which is what makes it the " +
			"handover record when a backup representative takes over a reporting case.",
		format:  FormatText,
		applies: bothClasses,
		ew:      RequirementOptional, n72: RequirementOptional, fr: RequirementOptional,
	},
	{
		id: FieldV16CSIRTNote, name: "CSIRT Note",
		desc: "Free-text note entered by the designated CSIRT for coordination and case handling. " +
			"Authored by the authority: this product must never write to it.",
		format:            FormatText,
		applies:           bothClasses,
		authorityAuthored: true,
		ew:                RequirementOptional, n72: RequirementOptional, fr: RequirementOptional,
	},
}

// BuildSRPGlossaryV16Schema returns the reporting schema transcribed from ENISA
// SRP Glossary v1.6.
//
// What makes this schema different from its predecessors, and why the change is
// not cosmetic: v1.6 publishes a requiredness value for every field at every
// stage, and the matrix is sparse. Most fields are NOT APPLICABLE outside one or
// two stages — the CVE identifier only exists at early warning, the severity and
// impact descriptions only at the final report, the attack vector only at 72
// hours. A schema that treats every field as available everywhere and carries
// values forward therefore disagrees with the form in both directions: it
// demands fields the platform rejects at that stage and it omits fields the
// platform requires. Validate enforces this, so the disagreement is an error
// rather than a note.
//
// Three fields the earlier schemas carried are deliberately absent: "evidence of
// active exploitation", "remediation and recovery outcome" and "reporting
// closure" have no position in any published glossary, and "reporting closure"
// is not a glossary field at all — the glossary states explicitly that reporting
// timestamps, the reporter identity and the stage selector are not fields. They
// were implementation-chosen identifiers presented alongside transcribed ones.
// The concepts remain in the workflow states; what ends here is the claim that
// they are SRP fields.
func BuildSRPGlossaryV16Schema(sourceKey string, publishedAt time.Time) (*ReportingSchema, error) {
	if sourceKey == "" {
		return nil, fmt.Errorf("regulatory: SRP glossary v1.6 schema requires the source key it was transcribed from")
	}
	s := &ReportingSchema{
		ID:          SchemaIDSRPGlossaryV16,
		Regime:      RegimeCRAArticle14,
		SourceKey:   sourceKey,
		PublishedAt: publishedAt,
		fields:      map[string]ReportingField{},
	}

	for _, row := range srp16Matrix {
		stages := make([]StageRequirement, 0, len(row.applies)*len(SchemaStages))
		for _, class := range row.applies {
			stages = append(stages,
				StageRequirement{Stage: StageEarlyWarning, EventClass: class, Requirement: row.ew},
				StageRequirement{Stage: StageNotification72h, EventClass: class, Requirement: row.n72},
				StageRequirement{Stage: StageFinalReport, EventClass: class, Requirement: row.fr},
			)
		}
		if err := s.AddField(ReportingField{
			ID:                 row.id,
			Name:               row.name,
			Description:        row.desc,
			Format:             row.format,
			EnumValues:         row.enum,
			MaxLength:          row.maxLen,
			ApplicableTo:       row.applies,
			AuthorityAuthored:  row.authorityAuthored,
			Stages:             stages,
			SourceKey:          sourceKey,
			IdentifierSourced:  true,
			IdentifierPosition: row.id,
		}); err != nil {
			return nil, fmt.Errorf("regulatory: SRP glossary v1.6 field %s: %w", row.id, err)
		}
	}
	return s, nil
}

// srpGlossaryV16Retained is the glossary text this schema was transcribed from,
// embedded so the hash in the registry can be recomputed from bytes that ship
// with the binary. A hash over a file that only exists on one developer's disk
// is not evidence.
//
//go:embed ENISA_SRP_GLOSSARY_v1.6.md
var srpGlossaryV16Retained []byte

const (
	srpGlossaryV16Version = "1.6"
	srpGlossaryV16URL     = "https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp/cra-srp-glossary2"
)

var (
	// srpGlossaryV16Published is the glossary's last-update date.
	srpGlossaryV16Published = time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	// srpGlossaryV16Retrieved is when this copy was retained.
	srpGlossaryV16Retrieved = time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
)

// SRPGlossaryV16Artifact returns the retained v1.6 glossary as provenance
// evidence.
//
// The hash covers the retained file, which is a normalised transcription rather
// than a byte copy of the published page — ENISA answers automated requests with
// HTTP 403. It therefore evidences "this is the text we transcribed", which is
// the claim the schema makes, and not "this is ENISA's HTML", which it does not
// make. The distinction is stated in the file itself as well, because a hash is
// only worth what its coverage is.
func SRPGlossaryV16Artifact() SourceArtifact {
	return NewSourceArtifact(
		DocSRPGlossary, srpGlossaryV16Version, srpGlossaryV16URL,
		srpGlossaryV16Retrieved, srpGlossaryV16Retained, "",
	)
}

// SRPGlossaryV16Source returns the v1.6 glossary as a registry source with its
// artifact attached, so SourceHash is computed from the retained text instead of
// from the document label.
func SRPGlossaryV16Source() Source {
	s := Source{
		Authority:       AuthorityENISAOperationalGuidance,
		Document:        DocSRPGlossary,
		Version:         srpGlossaryV16Version,
		PublicationDate: srpGlossaryV16Published,
		EffectiveFrom:   srpGlossaryV16Published,
		Supersedes:      "1.3",
	}
	s.AttachArtifact(SRPGlossaryV16Artifact())
	return s
}
