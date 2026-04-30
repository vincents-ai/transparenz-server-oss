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

// SlaTracking represents an SLA deadline entry for a vulnerability.
type SlaTracking struct {
	ID         uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	OrgID      uuid.UUID  `gorm:"type:uuid;not null;index:idx_sla_tracking_org_status;index:idx_sla_tracking_org_deadline" json:"org_id"`
	Cve        string     `gorm:"not null" json:"cve"`
	SbomID     *uuid.UUID `gorm:"index:idx_sla_tracking_org_status" json:"sbom_id,omitempty"`
	Deadline   time.Time  `gorm:"not null;index:idx_sla_tracking_org_deadline" json:"deadline"`
	Status     string     `gorm:"default:'pending';index:idx_sla_tracking_org_status" json:"status"`
	NotifiedAt *time.Time `json:"notified_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`

	Organization Organization `gorm:"foreignKey:OrgID;constraint:OnDelete:CASCADE" json:"-"`
}

func (SlaTracking) TableName() string {
	return "compliance.sla_tracking"
}
