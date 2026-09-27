// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.

package cra

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ErrAssessmentIncomplete is returned when an assessment does not carry
// enough evidence to open a report.
var ErrAssessmentIncomplete = errors.New("cra: assessment does not carry enough evidence to open a report")

// OpenRequest is a request to open a CRA report for one exposure found in an
// assessment.
//
// Opening a report is a human act with human inputs. Nothing in this package
// decides to open one: the caller names the exposure it has decided on, the
// event class, and the exploitation evidence it accepts. The function's job is
// to refuse when those inputs are not yet good enough, not to supply them.
type OpenRequest struct {
	// ReportID is assigned by the caller. Required — the report's identity
	// should be minted by the system that will audit it, not generated here.
	ReportID uuid.UUID

	// OrgID is the reporting manufacturer.
	OrgID uuid.UUID

	// ExposureProductID selects which product from the assessment is being
	// reported. An exposure that is not in the assessment cannot be reported:
	// the evidence for the composition is what the report stands on.
	ExposureProductID string

	// EventType is the reportable class. It is OPTIONAL and normally empty.
	//
	// A report opens at DETECTED with no class, because the class is the
	// determination itself and is recorded separately, with its reasoning and
	// actor, at the classification step. Accepting it here would let a report
	// be born already classified, which is the thing the two-step design exists
	// to prevent: a class asserted at open time has no determination behind it.
	//
	// It may be supplied when the caller genuinely determined the class while
	// preparing the record, in which case it is carried and the repository
	// still requires the determination to be recorded explicitly.
	EventType EventType

	// Exploitation is the evidence the human accepts. For an AEV this is
	// mandatory; the assessment's signals are the candidates, and picking among
	// them is a judgement.
	Exploitation *ExploitationEvidence

	// Awareness is the clock anchor. Required.
	Awareness Awareness

	// Actor is the person opening the report. Required: an Article 14 report
	// with no accountable actor behind it is not auditable.
	Actor string

	// Now is the opening instant. Required for determinism.
	Now time.Time
}

// OpenFromAssessment opens a report for one exposure of an assessment.
//
// This is the join between "we know where this vulnerability touches us" and
// "we are reporting a duty". It is deliberately explicit rather than
// automatic: the caller must name the product, the event class, the evidence
// and the awareness instant, and the function refuses if any of them is
// missing. A resolver that could open reports on its own would be making a
// statutory determination nobody authorised it to make.
func OpenFromAssessment(a Assessment, req OpenRequest) (Report, error) {
	if req.ReportID == uuid.Nil {
		return Report{}, fmt.Errorf("%w: no report id", ErrAssessmentIncomplete)
	}
	if req.OrgID == uuid.Nil {
		return Report{}, fmt.Errorf("%w: no reporting organisation", ErrAssessmentIncomplete)
	}
	if req.Actor == "" {
		return Report{}, fmt.Errorf("%w: no accountable actor", ErrAssessmentIncomplete)
	}
	if req.EventType != "" && !req.EventType.Valid() {
		return Report{}, fmt.Errorf("%w: event type %q is not valid", ErrAssessmentIncomplete, req.EventType)
	}
	if err := req.Awareness.Validate(); err != nil {
		return Report{}, fmt.Errorf("%w: %w", ErrAssessmentIncomplete, err)
	}
	if req.Now.IsZero() {
		return Report{}, fmt.Errorf("%w: no opening instant", ErrAssessmentIncomplete)
	}

	exposure, err := selectExposure(a, req.ExposureProductID)
	if err != nil {
		return Report{}, err
	}

	sbomID := exposure.SbomID
	r := Report{
		ID:              req.ReportID,
		OrgID:           req.OrgID,
		EventType:       req.EventType,
		State:           StateDetected,
		Awareness:       req.Awareness,
		VulnerabilityID: a.CVE,
		EUVDID:          a.EUVDID,
		// The report names the product and the component. The obligation is
		// owed in respect of the product; the component is how the
		// vulnerability reached it, and the SBOM is the evidence.
		ProductID:        exposure.ProductID,
		ProductName:      exposure.ProductName,
		SbomID:           &sbomID,
		ComponentName:    exposure.ComponentName,
		ComponentVersion: exposure.ComponentVersion,
		ComponentPURL:    exposure.ComponentPURL,
		Title: fmt.Sprintf("Actively exploited vulnerability %s in %s (%s)",
			a.CVE, exposure.ProductName, exposure.ComponentName),
		Description: fmt.Sprintf(
			"Component %s at version %s was identified in the product's SBOM with match confidence %q. "+
				"Composition evidence: SBOM %s, last observed %s.",
			exposure.ComponentName, exposure.ComponentVersion, exposure.MatchConfidence,
			exposure.SbomID, exposure.LatestScanAt.Format(time.RFC3339)),
		Exploitation: req.Exploitation,
		CreatedAt:    req.Now,
		UpdatedAt:    req.Now,
	}

	// Carry the assessment's evidence onto the report so the composition claim
	// survives into the reporting record. Without it, the report would assert
	// an obligation with no record of how the product was found to contain the
	// component.
	r.Decisions = append(r.Decisions, Decision{
		At:     req.Now,
		To:     StateDetected,
		Actor:  req.Actor,
		Reason: "report opened from an exposure assessment",
		Evidence: []string{
			fmt.Sprintf("product=%s sbom=%s component=%s@%s",
				exposure.ProductID, exposure.SbomID, exposure.ComponentName, exposure.ComponentVersion),
		},
	})
	if len(exposure.VexStatements) > 0 {
		for _, v := range exposure.VexStatements {
			r.Decisions = append(r.Decisions, Decision{
				At:     req.Now,
				To:     StateDetected,
				Actor:  req.Actor,
				Reason: fmt.Sprintf("existing VEX statement on record: status=%s justification=%s", v.Status, v.Justification),
				Evidence: []string{
					fmt.Sprintf("vex:%s", v.StatementID),
				},
			})
		}
	}
	return r, nil
}

// selectExposure finds a named product's exposure in an assessment.
func selectExposure(a Assessment, productID string) (PrioritisedExposure, error) {
	if productID == "" {
		if len(a.Prioritised) == 1 {
			return a.Prioritised[0], nil
		}
		return PrioritisedExposure{}, fmt.Errorf(
			"%w: the assessment covers %d products, so one must be named",
			ErrAssessmentIncomplete, len(a.Prioritised))
	}
	for _, e := range a.Prioritised {
		if e.ProductID == productID {
			return e, nil
		}
	}
	return PrioritisedExposure{}, fmt.Errorf(
		"%w: no exposure for product %q in this assessment", ErrAssessmentIncomplete, productID)
}
