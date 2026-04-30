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

// Scan represents a vulnerability scan executed against an SBOM.
type Scan struct {
	ID                   uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	OrgID                uuid.UUID `gorm:"type:uuid;not null;index:idx_scans_org_sbom,unique;index:idx_scans_org_date,unique" json:"org_id"`
	SbomID               uuid.UUID `gorm:"not null;index:idx_scans_org_sbom,unique" json:"sbom_id"`
	Status               string    `gorm:"default:'pending';index" json:"status"`
	ScanDate             time.Time `gorm:"default:NOW();index:idx_scans_org_date,unique" json:"scan_date"`
	ScannerVersion       string    `json:"scanner_version,omitempty"`
	ScannerSource        string    `gorm:"default:'grype'" json:"scanner_source,omitempty"`
	GvmReportID          string    `json:"gvm_report_id,omitempty"`
	VulnerabilitiesFound int       `gorm:"default:0" json:"vulnerabilities_found"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`

	Organization Organization `gorm:"foreignKey:OrgID;constraint:OnDelete:CASCADE" json:"-"`
}

func (Scan) TableName() string {
	return "compliance.scans"
}
