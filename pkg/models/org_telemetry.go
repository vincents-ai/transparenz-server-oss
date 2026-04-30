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

// OrgTelemetryConfig holds per-organization telemetry and metrics settings.
type OrgTelemetryConfig struct {
	ID                  uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	OrgID               uuid.UUID `gorm:"type:uuid;not null;uniqueIndex" json:"org_id"`
	Provider            string    `gorm:"not null;default:'prometheus'" json:"provider"`
	OtelEndpoint        string    `json:"otel_endpoint,omitempty"`
	OtelHeaders         JSONMap   `gorm:"type:jsonb;default:'{}'" json:"otel_headers,omitempty"`
	MetricsTokenHash    string    `gorm:"not null;uniqueIndex" json:"-"`
	MetricsTokenPrefix  string    `gorm:"type:varchar(16);index" json:"-"` // first 16 hex chars of SHA-256(token) for fast lookup
	Active              bool      `gorm:"not null;default:true" json:"active"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`

	Organization Organization `gorm:"foreignKey:OrgID;constraint:OnDelete:CASCADE" json:"-"`
}

func (OrgTelemetryConfig) TableName() string {
	return "compliance.org_telemetry_configs"
}
