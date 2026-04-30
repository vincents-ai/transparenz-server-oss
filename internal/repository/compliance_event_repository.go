// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/transparenz/transparenz-server-oss/internal/models"
	"gorm.io/gorm"
)

// ComplianceEventRepository provides data access for compliance audit events.
type ComplianceEventRepository struct {
	db *gorm.DB
}

// NewComplianceEventRepository creates a new ComplianceEventRepository backed by the given DB.
func NewComplianceEventRepository(db *gorm.DB) *ComplianceEventRepository {
	return &ComplianceEventRepository{db: db}
}

func (r *ComplianceEventRepository) Create(ctx context.Context, orgID uuid.UUID, event *models.ComplianceEvent) error {
	event.OrgID = orgID
	return r.db.WithContext(ctx).Create(event).Error
}

func (r *ComplianceEventRepository) List(ctx context.Context, limit, offset int) ([]models.ComplianceEvent, error) {
	var events []models.ComplianceEvent
	query := r.db.WithContext(ctx).Scopes(TenantScope(ctx)).Order("timestamp DESC")
	if limit > 0 {
		query = query.Limit(limit).Offset(offset)
	}
	err := query.Find(&events).Error
	return events, err
}

func (r *ComplianceEventRepository) ListByType(ctx context.Context, eventType string, limit, offset int) ([]models.ComplianceEvent, error) {
	var events []models.ComplianceEvent
	query := r.db.WithContext(ctx).Scopes(TenantScope(ctx)).Where("event_type = ?", eventType).Order("timestamp DESC")
	if limit > 0 {
		query = query.Limit(limit).Offset(offset)
	}
	err := query.Find(&events).Error
	return events, err
}

func (r *ComplianceEventRepository) GetLatestEventHash(ctx context.Context, orgID uuid.UUID) (string, error) {
	var event models.ComplianceEvent
	err := r.db.WithContext(ctx).
		Where("org_id = ?", orgID).
		Order("created_at DESC").
		Select("event_hash").
		First(&event).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", nil
		}
		return "", err
	}
	return event.EventHash, nil
}

func (r *ComplianceEventRepository) ListByDateRange(ctx context.Context, start, end time.Time) ([]models.ComplianceEvent, error) {
	var events []models.ComplianceEvent
	err := r.db.WithContext(ctx).
		Scopes(TenantScope(ctx)).
		Where("timestamp >= ? AND timestamp <= ?", start, end).
		Order("timestamp DESC").
		Find(&events).Error
	return events, err
}
