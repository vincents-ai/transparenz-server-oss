// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package repository

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
	"gorm.io/gorm"
)

var ErrSbomWebhookNotFound = errors.New("sbom webhook not found")

// SbomWebhookRepository provides data access for SBOM webhooks.
type SbomWebhookRepository struct {
	db *gorm.DB
}

// NewSbomWebhookRepository creates a new SbomWebhookRepository backed by the given DB.
func NewSbomWebhookRepository(db *gorm.DB) *SbomWebhookRepository {
	return &SbomWebhookRepository{db: db}
}

func (r *SbomWebhookRepository) GetWebhookByID(ctx context.Context, id uuid.UUID) (*models.SbomWebhook, error) {
	var webhook models.SbomWebhook
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&webhook).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrSbomWebhookNotFound
		}
		return nil, err
	}
	return &webhook, nil
}

func (r *SbomWebhookRepository) CreateWebhook(ctx context.Context, webhook *models.SbomWebhook) error {
	return r.db.WithContext(ctx).Create(webhook).Error
}

func (r *SbomWebhookRepository) ListWebhooksByOrg(ctx context.Context, orgID uuid.UUID, limit, offset int) ([]models.SbomWebhook, error) {
	var webhooks []models.SbomWebhook
	err := r.db.WithContext(ctx).
		Select("id", "org_id", "name", "actions", "active", "created_at", "updated_at", "last_used_at").
		Where("org_id = ?", orgID).
		Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&webhooks).Error
	return webhooks, err
}

func (r *SbomWebhookRepository) DeleteWebhook(ctx context.Context, id uuid.UUID, orgID uuid.UUID) error {
	result := r.db.WithContext(ctx).
		Where("id = ? AND org_id = ?", id, orgID).
		Delete(&models.SbomWebhook{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrSbomWebhookNotFound
	}
	return nil
}

func (r *SbomWebhookRepository) CountWebhooksByOrg(ctx context.Context, orgID uuid.UUID) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).
		Model(&models.SbomWebhook{}).
		Where("org_id = ?", orgID).
		Count(&count).Error
	return count, err
}
