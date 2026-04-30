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

// SigningKey represents an Ed25519 key pair used for compliance event signing.
type SigningKey struct {
	ID           uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	OrgID        uuid.UUID  `gorm:"type:uuid;not null;index" json:"org_id"`
	PublicKey    string     `gorm:"type:text;not null" json:"public_key"`
	KeyAlgorithm string     `gorm:"type:text;not null;default:'ed25519'" json:"key_algorithm"`
	CreatedAt    time.Time  `json:"created_at"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`

	Organization Organization `gorm:"foreignKey:OrgID;constraint:OnDelete:CASCADE" json:"-"`
}

func (SigningKey) TableName() string {
	return "compliance.signing_keys"
}
