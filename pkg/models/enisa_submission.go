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

// EnisaSubmission represents a CSAF document submitted to ENISA.
type EnisaSubmission struct {
	ID           uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	OrgID        uuid.UUID  `gorm:"type:uuid;not null;index:idx_enisa_submissions_org_status;index:idx_enisa_submissions_org_date" json:"org_id"`
	SubmissionID string     `gorm:"uniqueIndex" json:"submission_id,omitempty"`
	CsafDocument JSONMap    `gorm:"type:jsonb;not null" json:"csaf_document"`
	Status       string     `gorm:"default:'pending';index:idx_enisa_submissions_org_status" json:"status"`
	RetryCount   int        `gorm:"default:0" json:"retry_count"`
	SubmittedAt  *time.Time `gorm:"index:idx_enisa_submissions_org_date" json:"submitted_at,omitempty"`
	Response     JSONMap    `gorm:"type:jsonb" json:"response,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`

	Organization Organization `gorm:"foreignKey:OrgID;constraint:OnDelete:CASCADE" json:"-"`
}

func (EnisaSubmission) TableName() string {
	return "compliance.enisa_submissions"
}
