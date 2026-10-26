// SPDX-FileCopyrightText: 2026 Vincent Palmer
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Transparenz, an open-source CRA compliance server.
// It is licensed under the GNU Affero General Public License v3.0; see LICENSE.
package repository

import (
	"context"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
)

// VexPublicationRepository provides data access for VEX publication records.
type VexPublicationRepository struct {
	db *gorm.DB
}

// NewVexPublicationRepository creates a new VexPublicationRepository backed by the given DB.
func NewVexPublicationRepository(db *gorm.DB) *VexPublicationRepository {
	return &VexPublicationRepository{db: db}
}

func (r *VexPublicationRepository) Create(ctx context.Context, pub *models.VexPublication) error {
	return r.db.WithContext(ctx).Create(pub).Error
}

func (r *VexPublicationRepository) ListByVexID(ctx context.Context, vexID uuid.UUID) ([]models.VexPublication, error) {
	var pubs []models.VexPublication
	err := r.db.WithContext(ctx).
		Scopes(tenantScopeThroughParent(ctx, models.VexStatement{}.TableName(), "vex_id")).
		Where("vex_id = ?", vexID).
		Order("published_at DESC").
		Find(&pubs).Error
	return pubs, err
}

func (r *VexPublicationRepository) Update(ctx context.Context, pub *models.VexPublication) error {
	return r.db.WithContext(ctx).
		Scopes(tenantScopeThroughParent(ctx, models.VexStatement{}.TableName(), "vex_id")).
		Where("id = ?", pub.ID).
		Save(pub).Error
}
