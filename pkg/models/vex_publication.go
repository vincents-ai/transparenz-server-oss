// SPDX-FileCopyrightText: 2026 Vincent Palmer
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Transparenz, an open-source CRA compliance server.
// It is licensed under the GNU Affero General Public License v3.0; see LICENSE.
package models

import (
	"time"

	"github.com/google/uuid"
)

// VexPublication represents a published VEX statement via a specific channel.
type VexPublication struct {
	ID          uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	VexID       uuid.UUID `gorm:"type:uuid;not null;index:idx_vex_publications_vex" json:"vex_id"`
	PublishedAt time.Time `gorm:"not null" json:"published_at"`
	Channel     string    `gorm:"not null;check:channel" json:"channel"`
	Response    JSONMap   `gorm:"type:jsonb" json:"response,omitempty"`
	Status      string    `gorm:"not null;default:'pending';index:idx_vex_publications_status" json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`

	VexStatement VexStatement `gorm:"foreignKey:VexID;constraint:OnDelete:CASCADE" json:"-"`
}

func (VexPublication) TableName() string {
	return "compliance.vex_publications"
}
