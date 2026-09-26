// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package models

import (
	"time"

	"github.com/google/uuid"
)

// Obligation types recorded on SlaTracking.
const (
	// ObligationHandling is an internal vulnerability-handling window.
	ObligationHandling = "handling"

	// ObligationArticle14 is a CRA Article 14 reporting obligation.
	ObligationArticle14 = "article_14"
)

// Anchor names for SlaTracking.AnchorName.
const (
	// AnchorAwarenessAt is the manufacturer's awareness instant.
	AnchorAwarenessAt = "awareness_at"

	// AnchorDiscoveredAt is when we ingested the vulnerability.
	AnchorDiscoveredAt = "discovered_at"

	// AnchorKevDateAdded is CISA's feed date. A third party's clock, and
	// never a basis for a manufacturer's own regulatory deadline.
	AnchorKevDateAdded = "kev_date_added"

	// AnchorDetectionTime is when a scan observed the vulnerability in a
	// product. Operational, not regulatory.
	AnchorDetectionTime = "detection_time"
)

// SlaTracking represents a tracked deadline for a vulnerability. It carries
// either an internal handling window or a CRA Article 14 reporting obligation,
// and says which.
type SlaTracking struct {
	ID         uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	OrgID      uuid.UUID  `gorm:"type:uuid;not null;index:idx_sla_tracking_org_status;index:idx_sla_tracking_org_deadline" json:"org_id"`
	Cve        string     `gorm:"not null" json:"cve"`
	SbomID     *uuid.UUID `gorm:"index:idx_sla_tracking_org_status" json:"sbom_id,omitempty"`
	Deadline   time.Time  `gorm:"not null;index:idx_sla_tracking_org_deadline" json:"deadline"`
	Status     string     `gorm:"default:'pending';index:idx_sla_tracking_org_status" json:"status"`
	NotifiedAt *time.Time `json:"notified_at,omitempty"`

	// ObligationType separates the two duties that were previously conflated
	// into a single undifferentiated deadline.
	//
	// Before Article 14 enforcement, "KEV => 24h" and "critical => 72h" were
	// treated as the reporting clock. They are not the same thing: a critical
	// CVSS score is a triage heuristic with no regulatory standing, and active
	// exploitation is the actual Article 14 condition.
	//
	//	ObligationHandling    an internal vulnerability-handling window. Anchored
	//	                      on when we learned of the vulnerability. Driven by
	//	                      severity. NOT a reporting obligation.
	//	ObligationArticle14   a CRA Article 14 reporting obligation. Anchored on
	//	                      the manufacturer's awareness, with evidence. NOT
	//	                      driven by severity.
	ObligationType string `gorm:"not null;default:'handling'" json:"obligation_type"`

	// AnchorAt is the regulatory or operational event the deadline is measured
	// from, and AnchorName identifies which. Required for article_14 rows.
	// Retained alongside the computed deadline so "why is this date?" is
	// answerable without re-deriving it from mutable state.
	AnchorAt   *time.Time `json:"anchor_at,omitempty"`
	AnchorName string     `json:"anchor_name,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	Organization Organization `gorm:"foreignKey:OrgID;constraint:OnDelete:CASCADE" json:"-"`
}

func (SlaTracking) TableName() string {
	return "compliance.sla_tracking"
}
