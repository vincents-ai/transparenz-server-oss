// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package models

import (
	"database/sql/driver"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// ComplianceEvent represents an audit log entry in the compliance event chain.
type ComplianceEvent struct {
	ID                  uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	OrgID               uuid.UUID  `gorm:"type:uuid;not null;index:idx_compliance_events_org_type;index:idx_compliance_events_org_timestamp" json:"org_id"`
	EventType           string     `gorm:"not null;index:idx_compliance_events_org_type" json:"event_type"`
	Severity            string     `gorm:"not null" json:"severity"`
	Cve                 string     `json:"cve,omitempty"`
	ReportedToAuthority string     `json:"reported_to_authority,omitempty"`
	Timestamp           time.Time  `gorm:"default:NOW();index:idx_compliance_events_org_timestamp" json:"timestamp"`
	Metadata            JSONMap    `gorm:"type:jsonb;default:'{}'" json:"metadata"`
	Signature           string     `gorm:"type:text" json:"signature,omitempty"`
	SigningKeyID        *uuid.UUID `gorm:"type:uuid" json:"signing_key_id,omitempty"`
	PreviousEventHash   string     `gorm:"type:text" json:"previous_event_hash,omitempty"`
	EventHash           string     `gorm:"type:text" json:"event_hash,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`

	Organization Organization `gorm:"foreignKey:OrgID;constraint:OnDelete:CASCADE" json:"-"`
}

// JSONMap is a JSON-serializable map[string]interface{} type with GORM support.
type JSONMap map[string]interface{}

func (j JSONMap) Value() (driver.Value, error) {
	return json.Marshal(j)
}

func (j *JSONMap) Scan(value interface{}) error {
	bytes, ok := value.([]byte)
	if !ok {
		return nil
	}
	return json.Unmarshal(bytes, j)
}

func (j JSONMap) String() string {
	b, _ := json.Marshal(j)
	return string(b)
}

func (ComplianceEvent) TableName() string {
	return "compliance.compliance_events"
}
