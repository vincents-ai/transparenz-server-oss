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

type GRCMapping struct {
	ID              uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	OrgID           uuid.UUID  `gorm:"type:uuid;not null;index:idx_grc_mappings_org_vuln_ctrl,unique" json:"org_id"`
	VulnerabilityID *uuid.UUID `gorm:"type:uuid;index:idx_grc_mappings_org_vuln_ctrl,unique" json:"vulnerability_id,omitempty"`
	ControlID       string     `gorm:"not null;index:idx_grc_mappings_org_vuln_ctrl,unique" json:"control_id"`
	Framework       string     `gorm:"not null;index:idx_grc_mappings_framework" json:"framework"`
	MappingType     string     `gorm:"not null" json:"mapping_type"`
	Confidence      float64    `gorm:"type:decimal(5,4)" json:"confidence"`
	Evidence        string     `json:"evidence,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	Organization  Organization   `gorm:"foreignKey:OrgID;constraint:OnDelete:CASCADE" json:"-"`
	Vulnerability *Vulnerability `gorm:"foreignKey:VulnerabilityID;constraint:OnDelete:SET NULL" json:"vulnerability,omitempty"`
}

func (GRCMapping) TableName() string {
	return "compliance.grc_mappings"
}
