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

// GreenboneFinding represents an individual vulnerability finding from a Greenbone scan.
type GreenboneFinding struct {
	ID              uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	OrgID           uuid.UUID  `gorm:"type:uuid;not null;index" json:"org_id"`
	ScanID          uuid.UUID  `gorm:"type:uuid;not null;index" json:"scan_id"`
	GvmReportID     string     `gorm:"not null;index" json:"gvm_report_id"`
	GvmResultID     string     `gorm:"not null" json:"gvm_result_id"`
	GvmNvtOid       string     `gorm:"not null" json:"gvm_nvt_oid"`
	CVE             string     `json:"cve,omitempty"`
	Host            string     `gorm:"not null" json:"host"`
	Port            string     `json:"port,omitempty"`
	Severity        float64    `gorm:"type:decimal(5,1)" json:"severity"`
	Threat          string     `json:"threat,omitempty"`
	Name            string     `gorm:"not null" json:"name"`
	Description     string     `gorm:"type:text" json:"description,omitempty"`
	QoD             int        `gorm:"column:qod" json:"qod,omitempty"`
	VulnerabilityID *uuid.UUID `gorm:"type:uuid;index" json:"vulnerability_id,omitempty"`

	CreatedAt time.Time `json:"created_at"`

	Organization  Organization   `gorm:"foreignKey:OrgID;constraint:OnDelete:CASCADE" json:"-"`
	Scan          Scan           `gorm:"foreignKey:ScanID;constraint:OnDelete:CASCADE" json:"-"`
	Vulnerability *Vulnerability `gorm:"foreignKey:VulnerabilityID;constraint:OnDelete:SET NULL" json:"-"`
}

func (GreenboneFinding) TableName() string {
	return "compliance.greenbone_findings"
}
