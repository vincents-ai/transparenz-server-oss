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
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
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

// HasEventForReport reports whether a compliance event of the given type and
// STAGE has already been recorded against a CRA report.
//
// The stage is part of the key, and it has to be. A single report can miss both
// its 24-hour and its 72-hour window, and those are two separate failures that
// an authority would want to see separately. Keyed on report and type alone, the
// first one recorded would suppress every subsequent stage for that report, and
// the 72-hour miss would never be recorded at all.
//
// It exists so a ticker-driven sweeper records a breach once rather than on
// every tick. A 24-hour window that is breached stays breached, so without this
// a one-minute sweeper would write a duplicate audit event — and a duplicate in
// a signed hash chain is not a harmless repeat: it is a second, separately
// signed assertion that the same thing happened twice.
//
// The report id lives in the event's metadata, so this also keeps the audit
// record self-describing: an event names the report and the stage it concerns
// without needing a separate table.
func (r *ComplianceEventRepository) HasEventForReport(ctx context.Context, orgID uuid.UUID, eventType, reportID, stage string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).
		Model(&models.ComplianceEvent{}).
		Where("org_id = ? AND event_type = ? AND metadata->>'report_id' = ? AND metadata->>'stage' = ?",
			orgID, eventType, reportID, stage).
		Limit(1).
		Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}
