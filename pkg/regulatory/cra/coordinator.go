// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.

package cra

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// SelectionBasis records *why* a given CSIRT was identified as the appropriate
// coordinator. The manufacturer remains responsible for that determination —
// ENISA does not assign it, and no algorithm here can make it correctly.
type SelectionBasis string

const (
	// SelectionBasisEstablishmentCountry — the coordinator is the CSIRT of the
	// Member State where the manufacturer's establishment is situated.
	SelectionBasisEstablishmentCountry SelectionBasis = "establishment_country"

	// SelectionBasisEURepresentative — the manufacturer has no EU establishment
	// and reports through its authorised representative's Member State.
	SelectionBasisEURepresentative SelectionBasis = "eu_representative"

	// SelectionBasisMarketedIn — the product is placed on the market in
	// Member States whose CSIRT is competent for the affected products.
	SelectionBasisMarketedIn SelectionBasis = "marketed_in"

	// SelectionBasisAffectedUsers — the coordinator is determined by where
	// affected users are established, which is the CSIRT best placed to
	// support them.
	SelectionBasisAffectedUsers SelectionBasis = "affected_users"

	// SelectionBasisManualOverride — a human determined the coordinator by
	// some other means. Always audited, and always the weakest provenance.
	SelectionBasisManualOverride SelectionBasis = "manual_override"
)

// Valid reports whether b is a known selection basis.
func (b SelectionBasis) Valid() bool {
	switch b {
	case SelectionBasisEstablishmentCountry, SelectionBasisEURepresentative,
		SelectionBasisMarketedIn, SelectionBasisAffectedUsers,
		SelectionBasisManualOverride:
		return true
	}
	return false
}

// OrganisationProfile is the jurisdiction metadata that assists coordinator
// determination. It is metadata to support a human decision, not the decision.
type OrganisationProfile struct {
	// ManufacturerName is the legal manufacturer.
	ManufacturerName string `json:"manufacturer_name,omitempty"`

	// EstablishmentCountry is the ISO 3166-1 alpha-2 code of the Member State
	// where the manufacturer is established.
	EstablishmentCountry string `json:"establishment_country,omitempty"`

	// HasEUEstablishment distinguishes a manufacturer with an EU establishment
	// from one relying on an authorised representative. The distinction is
	// decisive for coordinator selection and is frequently the field
	// organisations forget to fill in.
	HasEUEstablishment bool `json:"has_eu_establishment"`

	// EURepresentative is the authorised representative's details, when the
	// manufacturer is established outside the EU.
	EURepresentative *EURepresentative `json:"eu_representative,omitempty"`

	// EstablishmentCountries are additional Member States in which the
	// manufacturer is established, for multi-establishment manufacturers.
	EstablishmentCountries []string `json:"establishment_countries,omitempty"`
}

// EURepresentative identifies the authorised representative.
type EURepresentative struct {
	Name    string `json:"name"`
	Country string `json:"country"`
	Email   string `json:"email,omitempty"`
}

// Coordinator is the CSIRT designated as coordinator (CDaC) selection for a
// report, with the provenance of that selection.
type Coordinator struct {
	// CsirtID identifies the CSIRT. Required once selected.
	CsirtID string `json:"csirt_id"`

	// Country is the Member State the CSIRT covers.
	Country string `json:"country,omitempty"`

	// Basis is why this CSIRT was selected. Required.
	Basis SelectionBasis `json:"basis"`

	// Justification is the human explanation. Required for a manual override;
	// recommended otherwise.
	Justification string `json:"justification,omitempty"`

	// SelectedBy is the principal that made the selection. Required.
	SelectedBy string `json:"selected_by,omitempty"`

	// SelectedAt is when the selection was made. Required.
	SelectedAt *time.Time `json:"selected_at,omitempty"`

	// Overridden reports that this selection replaced a previous one, together
	// with the prior value. A changed selection is exactly the kind of decision
	// an authority will ask about, so it is retained rather than overwritten.
	Overridden *OverriddenSelection `json:"overridden,omitempty"`
}

// OverriddenSelection retains a superseded coordinator selection.
type OverriddenSelection struct {
	CsirtID string         `json:"csirt_id"`
	Country string         `json:"country,omitempty"`
	Basis   SelectionBasis `json:"basis,omitempty"`
	At      time.Time      `json:"at"`
	By      string         `json:"by"`
	Reason  string         `json:"reason"`
}

// ErrCoordinatorUndetermined is returned when a submission is attempted without
// a selected coordinator. Filing to the wrong CSIRT is worse than not filing:
// the report is then genuinely lost, and the 24-hour obligation unmet.
var ErrCoordinatorUndetermined = errors.New("cra: no CSIRT designated as coordinator has been determined")

// SelectCoordinator validates and applies a coordinator selection, retaining
// any prior selection as an audited override.
func (r Report) SelectCoordinator(c Coordinator, now time.Time) (Report, error) {
	if c.CsirtID == "" {
		return r, ErrCoordinatorUndetermined
	}
	if !c.Basis.Valid() {
		return r, fmt.Errorf("cra: coordinator selection basis %q is not a known basis", c.Basis)
	}
	if c.SelectedBy == "" {
		return r, errors.New("cra: coordinator selection requires a recorded selector")
	}
	if c.Basis == SelectionBasisManualOverride && c.Justification == "" {
		return r, errors.New("cra: a manual coordinator override requires a written justification")
	}
	if c.SelectedAt == nil {
		t := now
		if t.IsZero() {
			t = time.Now()
		}
		c.SelectedAt = &t
	}
	if r.Coordinator != nil {
		prior := &OverriddenSelection{
			CsirtID: r.Coordinator.CsirtID,
			Country: r.Coordinator.Country,
			Basis:   r.Coordinator.Basis,
			At:      *c.SelectedAt,
			By:      c.SelectedBy,
			Reason:  c.Justification,
		}
		if prior.CsirtID != c.CsirtID {
			// Retain the chain rather than just the last one, so a selection
			// that has been changed twice is still reconstructible.
			if r.Coordinator.Overridden != nil {
				prior.Reason = strings.TrimSpace(prior.Reason + "; previously superseded: " + r.Coordinator.Overridden.Reason)
			}
			c.Overridden = prior
		}
	}
	r.Coordinator = &c
	return r, nil
}

// CandidateCoordinators returns the Member States whose CSIRTs the profile
// suggests, in the order ENISA's criteria would have them considered.
//
// It deliberately returns a ranked shortlist, not a decision, and it never
// returns a default. Defaulting every manufacturer to ENISA is the specific
// failure this function exists to prevent: it produces a confident-looking
// answer to a question the regulation reserves for the manufacturer.
func CandidateCoordinators(p OrganisationProfile) []SelectionCandidate {
	var out []SelectionCandidate
	seen := map[string]bool{}
	add := func(csirtID, country string, basis SelectionBasis, note string) {
		if csirtID == "" || seen[csirtID] {
			return
		}
		seen[csirtID] = true
		out = append(out, SelectionCandidate{
			CsirtID: csirtID, Country: country, Basis: basis, Note: note,
		})
	}
	if p.HasEUEstablishment {
		for _, c := range p.EstablishmentCountries {
			add(csirtIDForCountry(c), c, SelectionBasisEstablishmentCountry,
				"CSIRT of an additional EU establishment")
		}
		add(csirtIDForCountry(p.EstablishmentCountry), p.EstablishmentCountry,
			SelectionBasisEstablishmentCountry,
			"CSIRT of the Member State of the manufacturer's establishment")
	} else if p.EURepresentative != nil {
		add(csirtIDForCountry(p.EURepresentative.Country), p.EURepresentative.Country,
			SelectionBasisEURepresentative,
			"manufacturer established outside the EU; reports via its authorised representative")
	}
	return out
}

// SelectionCandidate is a suggested coordinator awaiting human confirmation.
type SelectionCandidate struct {
	CsirtID string         `json:"csirt_id"`
	Country string         `json:"country,omitempty"`
	Basis   SelectionBasis `json:"basis"`
	Note    string         `json:"note,omitempty"`
}

// csirtIDForCountry maps a Member State to its national CSIRT identifier.
// Kept as a small explicit table rather than a derived scheme, because the
// identifiers are the actual addressing information ENISA recognises and a
// derived format would be wrong for most of them.
func csirtIDForCountry(country string) string {
	if country == "" {
		return ""
	}
	return strings.ToUpper(country) + "-CSIRT"
}
