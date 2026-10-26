// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.

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
}

const (
	// filingFactsMaxText is the glossary's 255-character limit for the
	// manufacturer and product-version fields.
	filingFactsMaxText = 255

	// memberStateCodeLen is the length of an ISO 3166-1 alpha-2 code.
	memberStateCodeLen = 2
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
		ManufacturerName: strings.TrimSpace(f.ManufacturerName),
		ProductVersion:   strings.TrimSpace(f.ProductVersion),
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
