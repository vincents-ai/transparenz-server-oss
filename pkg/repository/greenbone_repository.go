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
	"github.com/transparenz/transparenz-server-oss/pkg/models"
	"gorm.io/gorm"
)

var ErrWebhookNotFound = errors.New("webhook not found")

// GreenboneRepository provides data access for Greenbone webhooks and findings.
type GreenboneRepository struct {
	db *gorm.DB
}

// NewGreenboneRepository creates a new GreenboneRepository backed by the given DB.
func NewGreenboneRepository(db *gorm.DB) *GreenboneRepository {
	return &GreenboneRepository{db: db}
}

func (r *GreenboneRepository) GetWebhookByID(ctx context.Context, id uuid.UUID) (*models.GreenboneWebhook, error) {
	var webhook models.GreenboneWebhook
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&webhook).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrWebhookNotFound
		}
		return nil, err
	}
	return &webhook, nil
}

func (r *GreenboneRepository) CreateWebhook(ctx context.Context, webhook *models.GreenboneWebhook) error {
	return r.db.WithContext(ctx).Create(webhook).Error
}

func (r *GreenboneRepository) ListWebhooksByOrg(ctx context.Context, orgID uuid.UUID, limit, offset int) ([]models.GreenboneWebhook, error) {
	var webhooks []models.GreenboneWebhook
	err := r.db.WithContext(ctx).
		Select("id", "org_id", "name", "actions", "active", "created_at", "updated_at", "last_used_at").
		Where("org_id = ?", orgID).
		Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&webhooks).Error
	return webhooks, err
}

func (r *GreenboneRepository) DeleteWebhook(ctx context.Context, id uuid.UUID, orgID uuid.UUID) error {
	result := r.db.WithContext(ctx).
		Where("id = ? AND org_id = ?", id, orgID).
		Delete(&models.GreenboneWebhook{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrWebhookNotFound
	}
	return nil
}

func (r *GreenboneRepository) CountWebhooksByOrg(ctx context.Context, orgID uuid.UUID) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).
		Model(&models.GreenboneWebhook{}).
		Where("org_id = ?", orgID).
		Count(&count).Error
	return count, err
}

func (r *GreenboneRepository) CreateFinding(ctx context.Context, finding *models.GreenboneFinding) error {
	return r.db.WithContext(ctx).Create(finding).Error
}

func (r *GreenboneRepository) CreateFindingsBatch(ctx context.Context, findings []models.GreenboneFinding) error {
	if len(findings) == 0 {
		return nil
	}
	return r.db.WithContext(ctx).Create(&findings).Error
}

func (r *GreenboneRepository) ReportExists(ctx context.Context, orgID uuid.UUID, gvmReportID string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).
		Model(&models.Scan{}).
		Where("org_id = ? AND gvm_report_id = ? AND scanner_source = 'greenbone'", orgID, gvmReportID).
		Count(&count).Error
	return count > 0, err
}
