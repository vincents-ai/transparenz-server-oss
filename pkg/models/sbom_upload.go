// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// SbomUpload represents an uploaded Software Bill of Materials document.
type SbomUpload struct {
	ID        uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	OrgID     uuid.UUID       `gorm:"type:uuid;not null" json:"org_id"`
	Filename  string          `gorm:"not null" json:"filename"`
	Format    string          `gorm:"not null" json:"format"`
	SizeBytes int64           `gorm:"not null" json:"size_bytes"`
	SHA256    string          `gorm:"not null" json:"sha256"`
	Document  json.RawMessage `gorm:"type:jsonb;not null" json:"-"`
	CreatedAt time.Time       `json:"created_at"`

	Organization Organization `gorm:"foreignKey:OrgID;constraint:OnDelete:CASCADE" json:"-"`
}

func (SbomUpload) TableName() string {
	return "compliance.sbom_uploads"
}
