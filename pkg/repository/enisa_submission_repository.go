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

var ErrEnisaSubmissionNotFound = errors.New("enisa submission not found")

// EnisaSubmissionRepository provides data access for ENISA submissions.
type EnisaSubmissionRepository struct {
	db *gorm.DB
}

// NewEnisaSubmissionRepository creates a new EnisaSubmissionRepository backed by the given DB.
func NewEnisaSubmissionRepository(db *gorm.DB) *EnisaSubmissionRepository {
	return &EnisaSubmissionRepository{db: db}
}

func (r *EnisaSubmissionRepository) Create(ctx context.Context, orgID uuid.UUID, submission *models.EnisaSubmission) error {
	submission.OrgID = orgID
	return r.db.WithContext(ctx).Create(submission).Error
}

func (r *EnisaSubmissionRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.EnisaSubmission, error) {
	var submission models.EnisaSubmission
	err := r.db.WithContext(ctx).Scopes(TenantScope(ctx)).Where("id = ?", id).First(&submission).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrEnisaSubmissionNotFound
		}
		return nil, err
	}
	return &submission, nil
}

func (r *EnisaSubmissionRepository) Count(ctx context.Context) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&models.EnisaSubmission{}).
		Scopes(TenantScope(ctx)).
		Count(&count).Error
	return count, err
}

func (r *EnisaSubmissionRepository) List(ctx context.Context, limit, offset int) ([]models.EnisaSubmission, error) {
	var submissions []models.EnisaSubmission
	query := r.db.WithContext(ctx).Scopes(TenantScope(ctx)).Order("created_at DESC")
	if limit > 0 {
		query = query.Limit(limit).Offset(offset)
	}
	err := query.Find(&submissions).Error
	return submissions, err
}

func (r *EnisaSubmissionRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status string) error {
	return r.db.WithContext(ctx).Model(&models.EnisaSubmission{}).
		Scopes(TenantScope(ctx)).
		Where("id = ?", id).
		Update("status", status).Error
}

// Cross-tenant: intentionally called from background workers without tenant context.
func (r *EnisaSubmissionRepository) ListFailedForRetry(ctx context.Context, maxRetries int) ([]models.EnisaSubmission, error) {
	var submissions []models.EnisaSubmission
	err := r.db.WithContext(ctx).
		Where("status = 'failed' AND retry_count < ?", maxRetries).
		Order("updated_at ASC").
		Find(&submissions).Error
	return submissions, err
}

func (r *EnisaSubmissionRepository) IncrementRetry(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Model(&models.EnisaSubmission{}).
		Where("id = ?", id).
		UpdateColumn("retry_count", gorm.Expr("retry_count + 1")).Error
}
