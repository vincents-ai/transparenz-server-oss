// SPDX-FileCopyrightText: 2026 Vincent Palmer
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Transparenz, an open-source CRA compliance server.
// It is licensed under the GNU Affero General Public License v3.0; see LICENSE.

package cra

import (
	"fmt"
	"strings"
)

// FilingFacts are the report-level facts every SRP filing asks for that are not
// about the vulnerability or the incident itself.
//
// They live on the report because they are properties of the product and the
// manufacturer, not of the notification. Filing them per stage, typed by hand,
// is how the same product ends up named slightly differently in the early
// warning and the final report.
type FilingFacts struct {
	// ManufacturerName is the natural or legal person who develops or
	// manufactures the product, or has it designed or manufactured, and markets
	// it under its name or trademark.
	//
	// It is NOT the organisation's account name. Those coincide for many users of
	// this product and diverge for an importer, a rebrander, or an OEM
	// arrangement — and a regulatory filing naming the wrong legal person is a
	// defect an authority notices.
	ManufacturerName string

	// ProductVersion identifies the affected versions. The glossary allows a
	// range to be stated explicitly, which is what most cases need.
	ProductVersion string

	// MemberStates are the ISO 3166-1 alpha-2 codes of the Member States in which
	// the manufacturer is aware the affected product has been made available.
	//
	// This is not bookkeeping: the SRP derives the concerned CSIRTs from it, and
	// the coordinating CSIRT disseminates to them. An incomplete list under-reports
	// the incident to the authorities of the States where the product is in use.
	MemberStates []string

	// The written statements the SRP asks for.
	//
	// They are held once per case rather than per stage, because they are
	// statements about the case. Typing them again for each stages is how a final
	// report ends up describing a severity the 72-hour notification contradicted.
	// Each is derived into whichever glossary position the event class uses, so
	// there is one text per fact and one place to correct it.

	// SeverityDescription is SRP v24 for an AEV and i34 for a severe incident.
	SeverityDescription string

	// ImpactDescription is SRP v25 for an AEV and i35 for a severe incident.
	ImpactDescription string

	// MeasuresTaken is SRP 16 for both classes, and i33 for a severe incident.
	MeasuresTaken string

	// MeasuresForUsers is SRP 17.
	MeasuresForUsers string

	// UserAction is SRP 14: what users can do now to reduce impact.
	UserAction string

	// GeneralInformation is SRP v21 for an AEV and i32 for a severe incident: the
	// 72-hour narrative.
	GeneralInformation string

	// InitialAssessment is SRP i39, the severe-incident preliminary analysis.
	InitialAssessment string

	// UpdateDetails is SRP v23, the details of the available security update.
	UpdateDetails string

	// RootCause is SRP i36: the type of threat or root cause likely to have
	// triggered a severe incident.
	RootCause string

	// IncidentSuspected is SRP i31: whether a severe incident is suspected of
	// unlawful or malicious acts. The article requires it at the early warning, so
	// without it the first stage of a severe incident cannot be filed at all.
	IncidentSuspected string
}

const (
	// filingFactsMaxText is the glossary's 255-character limit for the
	// manufacturer and product-version fields.
	filingFactsMaxText = 255

	// memberStateCodeLen is the length of an ISO 3166-1 alpha-2 code.
	memberStateCodeLen = 2

	// The glossary's character limits for the written statements. 2000 for SRP 16
	// and v23, 4000 for the rest.
	narrativeMax2000 = 2000
	narrativeMax4000 = 4000
	narrativeMax255  = 255
)

// Validate reports whether the facts are complete enough to build a filing from.
//
// Every refusal here is one the SRP form would make later, at the point where a
// human is on a deadline, so making them at the point of recording is the whole
// benefit.
func (f FilingFacts) Validate() error {
	if strings.TrimSpace(f.ManufacturerName) == "" {
		return fmt.Errorf("%w: the manufacturer is a legal person and must be named", ErrInvalidReport)
	}
	if len(strings.TrimSpace(f.ManufacturerName)) > filingFactsMaxText {
		return fmt.Errorf("%w: the manufacturer name exceeds %d characters", ErrInvalidReport, filingFactsMaxText)
	}
	if strings.TrimSpace(f.ProductVersion) == "" {
		return fmt.Errorf("%w: the affected product version is required; state a range where several versions are affected", ErrInvalidReport)
	}
	if len(strings.TrimSpace(f.ProductVersion)) > filingFactsMaxText {
		return fmt.Errorf("%w: the product version exceeds %d characters", ErrInvalidReport, filingFactsMaxText)
	}
	if len(f.MemberStates) == 0 {
		return fmt.Errorf("%w: at least one Member State is required; it decides which CSIRTs are concerned", ErrInvalidReport)
	}

	// The narratives are optional here because each is required at a specific
	// stage, and which stage depends on the event class — the reporting schema
	// enforces that when a package is built. What is checked here is the glossary's
	// character limit, so a statement that cannot be filed is refused at the point
	// it is written rather than at 03:00 on a deadline.
	for _, n := range []struct {
		name  string
		value string
		limit int
	}{
		{"severity description (v24/i34)", f.SeverityDescription, narrativeMax4000},
		{"impact description (v25/i35)", f.ImpactDescription, narrativeMax4000},
		{"measures taken (16/i33)", f.MeasuresTaken, narrativeMax2000},
		{"measures users can take (17)", f.MeasuresForUsers, narrativeMax4000},
		{"user action (14)", f.UserAction, narrativeMax4000},
		{"general information (v21/i32)", f.GeneralInformation, narrativeMax4000},
		{"initial assessment (i39)", f.InitialAssessment, narrativeMax4000},
		{"update details (v23)", f.UpdateDetails, narrativeMax2000},
		{"root cause (i36)", f.RootCause, narrativeMax255},
		{"incident suspected (i31)", f.IncidentSuspected, narrativeMax255},
	} {
		if len(strings.TrimSpace(n.value)) > n.limit {
			return fmt.Errorf("%w: %s exceeds the %d characters the glossary allows",
				ErrInvalidReport, n.name, n.limit)
		}
	}

	seen := map[string]bool{}
	for _, code := range f.MemberStates {
		if len(code) != memberStateCodeLen || !isUpperAlpha(code) {
			return fmt.Errorf("%w: %q is not an ISO 3166-1 alpha-2 Member State code", ErrInvalidReport, code)
		}
		if seen[code] {
			return fmt.Errorf("%w: Member State %q is listed twice", ErrInvalidReport, code)
		}
		seen[code] = true
	}
	return nil
}

func isUpperAlpha(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 'A' || s[i] > 'Z' {
			return false
		}
	}
	return true
}

// Normalised returns the facts in the form they are stored and filed: trimmed,
// with Member States uppercased and de-duplicated in a stable order.
//
// Normalising rather than rejecting a lowercase code is deliberate. Lowercase is
// a presentation habit, not a legal statement, and refusing it would train people
// to fight the form; an unexpected code is a different matter and is refused.
func (f FilingFacts) Normalised() FilingFacts {
	out := FilingFacts{
		ManufacturerName:    strings.TrimSpace(f.ManufacturerName),
		ProductVersion:      strings.TrimSpace(f.ProductVersion),
		SeverityDescription: strings.TrimSpace(f.SeverityDescription),
		ImpactDescription:   strings.TrimSpace(f.ImpactDescription),
		MeasuresTaken:       strings.TrimSpace(f.MeasuresTaken),
		MeasuresForUsers:    strings.TrimSpace(f.MeasuresForUsers),
		UserAction:          strings.TrimSpace(f.UserAction),
		GeneralInformation:  strings.TrimSpace(f.GeneralInformation),
		InitialAssessment:   strings.TrimSpace(f.InitialAssessment),
		UpdateDetails:       strings.TrimSpace(f.UpdateDetails),
		RootCause:           strings.TrimSpace(f.RootCause),
		IncidentSuspected:   strings.TrimSpace(f.IncidentSuspected),
	}
	seen := map[string]bool{}
	for _, code := range f.MemberStates {
		code = strings.ToUpper(strings.TrimSpace(code))
		if code == "" || seen[code] {
			continue
		}
		seen[code] = true
		out.MemberStates = append(out.MemberStates, code)
	}
	return out
}
