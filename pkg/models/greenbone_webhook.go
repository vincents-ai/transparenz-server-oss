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

// GreenboneWebhookActions defines which actions are triggered by a Greenbone webhook.
type GreenboneWebhookActions struct {
	StoreFindings     bool   `json:"store_findings" gorm:"-"`
	BroadcastAlerts   bool   `json:"broadcast_alerts" gorm:"-"`
	TriggerSLA        bool   `json:"trigger_sla" gorm:"-"`
	GenerateCSAF      bool   `json:"generate_csaf" gorm:"-"`
	EmitOTel          bool   `json:"emit_otel" gorm:"-"`
	SeverityThreshold string `json:"severity_threshold" gorm:"-"`
}

func (a GreenboneWebhookActions) Value() (driver.Value, error) {
	return json.Marshal(a)
}

func (a *GreenboneWebhookActions) Scan(value interface{}) error {
	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, a)
	case string:
		return json.Unmarshal([]byte(v), a)
	default:
		return fmt.Errorf("failed to scan GreenboneWebhookActions: unsupported type %T", value)
	}
}

// GreenboneWebhook represents an inbound Greenbone webhook configuration.
type GreenboneWebhook struct {
	ID            uuid.UUID               `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	OrgID         uuid.UUID               `gorm:"type:uuid;not null;index" json:"org_id"`
	Name          string                  `gorm:"not null" json:"name"`
	SecretHash    string                  `gorm:"not null" json:"-"`
	// SigningSecret is stored in plaintext because it is needed at runtime to verify
	// incoming webhook HMAC signatures. If database-level secret protection is required,
	// derive signing keys server-side using HMAC(server_key, webhook_id) instead of storing
	// a random secret per webhook. This would require a migration of existing webhooks.
	SigningSecret string                  `gorm:"default:''" json:"-"`
	Actions       GreenboneWebhookActions `gorm:"type:jsonb;default:'{}'" json:"actions"`
	Active        bool                    `gorm:"default:true" json:"active"`

	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`

	Organization Organization `gorm:"foreignKey:OrgID;constraint:OnDelete:CASCADE" json:"-"`
}

func (GreenboneWebhook) TableName() string {
	return "compliance.greenbone_webhooks"
}
