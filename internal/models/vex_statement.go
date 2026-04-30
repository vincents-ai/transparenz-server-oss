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

// VexStatement represents a VEX vulnerability exploitation statement.
type VexStatement struct {
	ID              uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	OrgID           uuid.UUID  `gorm:"type:uuid;not null;index:idx_vex_statements_org" json:"org_id"`
	CVE             string     `gorm:"not null;index:idx_vex_statements_cve" json:"cve"`
	ProductID       string     `gorm:"not null;default:''" json:"product_id"`
	Justification   string     `gorm:"not null;check:justification" json:"justification"`
	ImpactStatement string     `gorm:"type:text;default:''" json:"impact_statement"`
	Confidence      string     `gorm:"not null;default:'unknown';check:confidence" json:"confidence"`
	ValidUntil      *time.Time `json:"valid_until,omitempty"`
	Status          string     `gorm:"not null;default:'draft';index:idx_vex_statements_status" json:"status"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`

	Organization Organization `gorm:"foreignKey:OrgID;constraint:OnDelete:CASCADE" json:"-"`
}

func (VexStatement) TableName() string {
	return "compliance.vex_statements"
}
