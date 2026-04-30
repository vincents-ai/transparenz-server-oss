// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// SbomWebhookActions defines which actions are triggered by an SBOM webhook.
type SbomWebhookActions struct {
	TriggerScan     bool `json:"trigger_scan" gorm:"-"`
	BroadcastAlerts bool `json:"broadcast_alerts" gorm:"-"`
	TriggerSLA      bool `json:"trigger_sla" gorm:"-"`
	EmitOTel        bool `json:"emit_otel" gorm:"-"`
}

func (a SbomWebhookActions) Value() (driver.Value, error) {
	return json.Marshal(a)
}

func (a *SbomWebhookActions) Scan(value interface{}) error {
	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, a)
	case string:
		return json.Unmarshal([]byte(v), a)
	default:
		return fmt.Errorf("failed to scan SbomWebhookActions: unsupported type %T", value)
	}
}

// SbomWebhook represents an inbound SBOM webhook configuration.
type SbomWebhook struct {
	ID            uuid.UUID          `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	OrgID         uuid.UUID          `gorm:"type:uuid;not null;index" json:"org_id"`
	Name          string             `gorm:"not null" json:"name"`
	SecretHash    string             `gorm:"not null" json:"-"`
	// SigningSecret is stored in plaintext because it is needed at runtime to verify
	// incoming webhook HMAC signatures. See GreenboneWebhook for same pattern.
	SigningSecret string             `gorm:"default:''" json:"-"`
	Actions       SbomWebhookActions `gorm:"type:jsonb;default:'{}'" json:"actions"`
	Active        bool               `gorm:"default:true" json:"active"`

	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`

	Organization Organization `gorm:"foreignKey:OrgID;constraint:OnDelete:CASCADE" json:"-"`
}

func (SbomWebhook) TableName() string {
	return "compliance.sbom_webhooks"
}
