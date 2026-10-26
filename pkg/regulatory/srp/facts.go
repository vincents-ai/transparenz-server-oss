// SPDX-FileCopyrightText: 2026 Vincent Palmer
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Transparenz, an open-source CRA compliance server.
// It is licensed under the GNU Affero General Public License v3.0; see LICENSE.

package srp

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/vincents-ai/transparenz-server-oss/pkg/regulatory"
)

// ReportFacts are the facts a stored report contributes to a package.
//
// It exists so the field values a package is built from can come from the record
// of the case rather than being re-typed into a form. Re-typing is not merely
// tedious: a value transcribed by hand can drift from the report, and the filing
// then contradicts the case file it claims to report. Every field here is
// derived from something the report already holds.
//
// What is deliberately NOT here, because the report does not hold it or does not
// hold something equivalent:
//
//   - PEC grounds (v28-v30). cra.PECGrounds are the product's own vocabulary
//     (active remediation, operational security, law enforcement, personal
//     data). The SRP's three options are the Article 16(2) circumstances —
//     confined to the coordinating CSIRT's Member State, national security or
//     defence, imminent high risk. They are not the same taxonomy, and mapping
//     one onto the other would assert a legal ground the filer never chose.
//   - When the vulnerability or incident OCCURRED (v26a, i38). The report holds
//     when exploitation was observed, which is when we saw it, not when it
//     started.
//
// The written statements (v24/v25/i34/i35, 16/17/i33, 14, v21/i32, i39, v23) ARE
// carried, from columns on the report. They are prose a human writes and nothing
// generates them, but writing them once per case rather than once per stage is
// what stops a final report describing a severity the 72-hour notification
// contradicted.
type ReportFacts struct {
	// Title and Summary are the report's own title and description.
	Title   string
	Summary string

	// ProductName and ProductVersion identify the affected product.
	ProductName    string
	ProductVersion string

	// ManufacturerName is the legal person marketing the product. It is recorded
	// on the report and deliberately never inferred from the organisation, which
	// is an account rather than a manufacturer.
	ManufacturerName string

	// MemberStates are the Member States in which the product is available,
	// already rendered for filing (e.g. "Germany; Netherlands"). The report stores
	// ISO codes; the SRP form takes a list.
	MemberStates string

	// ComponentName and ComponentVersion identify the affected component, where
	// the issue is attributable to one.
	ComponentName    string
	ComponentVersion string

	// CVE and EUVDID are the identifiers recorded on the report. Either may be
	// absent: an early warning frequently precedes a CVE assignment.
	CVE    string
	EUVDID string

	// Actor is what the report records about attribution, if anything.
	Actor string

	// AttackVector is the report's structured vector classification.
	AttackVector string

	// MitigationAvailableAt is the instant a corrective or mitigating measure
	// became available. It anchors the AEV final-report deadline and is also the
	// fact field v22 asks for, so it is filed from the same value the deadline
	// was computed from.
	MitigationAvailableAt *time.Time

	// The written statements. Each maps to one glossary position per event class,
	// so the same text serves an AEV (v24) and a severe incident (i34).
	SeverityDescription string
	ImpactDescription   string
	MeasuresTaken       string
	MeasuresForUsers    string
	UserAction          string
	GeneralInformation  string
	InitialAssessment   string
	UpdateDetails       string
	RootCause           string
	IncidentSuspected   string
}

// ErrDerivedFieldConflict is returned when a caller supplies a value for a field
// the report already determines, and the two disagree.
//
// Silently preferring either one is wrong in a different way: preferring the
// caller lets the filing drift from the case file, and preferring the report
// hides that somebody thought the report was wrong. The disagreement is the
// information, so it is returned.
var ErrDerivedFieldConflict = errors.New("srp: field is derived from the report and the supplied value disagrees with it")

// NotificationTypeFor returns the v1.6 notification-type value for an event
// class: field 1 is a select of Vulnerability or Incident.
func NotificationTypeFor(class regulatory.EventClass) (string, bool) {
	switch class {
	case regulatory.EventClassAEV:
		return "Vulnerability", true
	case regulatory.EventClassSI:
		return "Incident", true
	default:
		return "", false
	}
}

// deriveFields returns the field values the report determines for this stage.
//
// A field is derived only when it APPLIES at the requested stage. That is not a
// detail: in v1.6 most fields are not applicable outside one or two stages, and a
// final report that carried the early warning's title would be rejected by the
// platform — so a derivation that ignored the stage would turn a helpful feature
// into a guaranteed submission failure.
func deriveFields(schema *regulatory.ReportingSchema, stage regulatory.Stage, class regulatory.EventClass, facts ReportFacts) map[string]string {
	out := map[string]string{}

	add := func(id, value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		f, defined := schema.Field(id)
		if !defined {
			// The schema predates the glossary position, e.g. V2. Deriving a
			// field it does not define would fail validation for a reason that
			// has nothing to do with the caller.
			return
		}
		if f.RequirementAt(stage, class) == regulatory.RequirementNotApplicable {
			return
		}
		out[id] = value
	}

	if v, ok := NotificationTypeFor(class); ok {
		add(regulatory.FieldV16NotificationType, v)
	}
	add(regulatory.FieldV16Title, facts.Title)
	add(regulatory.FieldV16Summary, facts.Summary)
	add(regulatory.FieldV16ProductName, facts.ProductName)
	add(regulatory.FieldV16ProductVersion, facts.ProductVersion)
	add(regulatory.FieldV16ManufacturerName, facts.ManufacturerName)
	add(regulatory.FieldV16MemberStates, facts.MemberStates)

	// v12 asks for the component and, where known, its version, in one field.
	component := facts.ComponentName
	if component != "" && facts.ComponentVersion != "" {
		component = component + " " + facts.ComponentVersion
	}
	add(regulatory.FieldV16ComponentName, component)

	add(regulatory.FieldV16CVEID, facts.CVE)
	add(regulatory.FieldV16EUVDID, facts.EUVDID)
	add(regulatory.FieldV16Actor, facts.Actor)
	add(regulatory.FieldV16AttackVector, facts.AttackVector)

	// v22 is derived only where it stands alone. At the early warning and 72-hour
	// stages v1.6 makes it "Optional (after completion of v17)" — the date cannot
	// be given before the measures-users-can-take text is complete. Deriving it
	// there would fill a field the platform expects to be gated on another one, so
	// it is left to the filer, who can see whether 17 is complete. At the final
	// report it is required outright, which is where the report's own mitigation
	// instant is filed.
	// The written statements, into the position the event class uses.
	add(regulatory.FieldV16MeasuresTaken, facts.MeasuresTaken)
	add(regulatory.FieldV16MeasuresForUsers, facts.MeasuresForUsers)
	add(regulatory.FieldV16UserAction, facts.UserAction)

	switch class {
	case regulatory.EventClassAEV:
		add(regulatory.FieldV16SeverityDesc, facts.SeverityDescription)
		add(regulatory.FieldV16ImpactDesc, facts.ImpactDescription)
		add(regulatory.FieldV16GeneralInfo, facts.GeneralInformation)
		add(regulatory.FieldV16UpdateDetails, facts.UpdateDetails)
	case regulatory.EventClassSI:
		add(regulatory.FieldV16IncidentSeverity, facts.SeverityDescription)
		add(regulatory.FieldV16IncidentImpact, facts.ImpactDescription)
		add(regulatory.FieldV16IncidentNature, facts.GeneralInformation)
		add(regulatory.FieldV16IncidentAssessment, facts.InitialAssessment)
		add(regulatory.FieldV16IncidentRootCause, facts.RootCause)
		// i33 is the severe-incident statement of the measures taken.
		add(regulatory.FieldV16IncidentMeasures, facts.MeasuresTaken)
		// i31 is required at the severe-incident early warning.
		add(regulatory.FieldV16IncidentSuspected, facts.IncidentSuspected)
	}

	if facts.MitigationAvailableAt != nil {
		if f, ok := schema.Field(regulatory.FieldV16MeasureDate); ok &&
			f.RequirementAt(stage, class) == regulatory.RequirementRequired {
			add(regulatory.FieldV16MeasureDate, regulatory.SRPTimestamp(*facts.MitigationAvailableAt))
		}
	}

	return out
}

// mergeDerived layers the report's facts under the caller's values.
//
// Where both name the same field the values must agree. Agreement is not an
// error — a caller restating what the report already says is doing no harm — but
// a disagreement means either the report is stale or the package is, and that
// has to be resolved rather than papered over.
func mergeDerived(fields map[string]string, derived map[string]string) error {
	for id, want := range derived {
		if got, supplied := fields[id]; supplied && strings.TrimSpace(got) != want {
			return fmt.Errorf("%w: field %s is %q on the report but %q was supplied; "+
				"correct the report rather than the package", ErrDerivedFieldConflict, id, want, got)
		}
		fields[id] = want
	}
	return nil
}
