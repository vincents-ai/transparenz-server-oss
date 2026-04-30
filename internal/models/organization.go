// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package models

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Organization represents a tenant organization with compliance settings.
type Organization struct {
	ID   uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	Name string    `gorm:"not null" json:"name"`
	Slug string    `gorm:"uniqueIndex;not null" json:"slug"`

	EnisaSubmissionMode string `gorm:"default:'export'" json:"enisa_submission_mode"`
	CsafScope           string `gorm:"default:'per_sbom'" json:"csaf_scope"`
	PdfTemplate         string `gorm:"default:'generic'" json:"pdf_template"`
	SlaTrackingMode     string `gorm:"default:'per_cve'" json:"sla_tracking_mode"`

	Tier            string `gorm:"not null;default:'standard'" json:"tier"`
	SlaMode         string `gorm:"not null;default:'alerts_only'" json:"sla_mode"`
	MultiTenantMode string `gorm:"column:multi_tenant_mode;default:'shared'" json:"multi_tenant_mode,omitempty"`

	EnisaAPIEndpoint     string `json:"enisa_api_endpoint,omitempty"`
	EnisaAPIKeyEncrypted string `json:"-" gorm:"column:enisa_api_key_encrypted"`

	SupportPeriodMonths int        `gorm:"default:60" json:"support_period_months"`
	SupportStartDate    *time.Time `json:"support_start_date,omitempty"`
	SupportEndDate      *time.Time `json:"support_end_date,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (o *Organization) ValidateSupportPeriod() error {
	if o.SupportPeriodMonths < 12 {
		return fmt.Errorf("support_period_months must be >= 12, got %d", o.SupportPeriodMonths)
	}
	return nil
}

func (Organization) TableName() string {
	return "compliance.organizations"
}
