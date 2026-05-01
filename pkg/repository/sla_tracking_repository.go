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

var ErrSlaTrackingNotFound = errors.New("sla tracking not found")

// SlaTrackingRepository provides data access for SLA tracking records.
type SlaTrackingRepository struct {
	db *gorm.DB
}

// NewSlaTrackingRepository creates a new SlaTrackingRepository backed by the given DB.
func NewSlaTrackingRepository(db *gorm.DB) *SlaTrackingRepository {
	return &SlaTrackingRepository{db: db}
}

func (r *SlaTrackingRepository) Create(ctx context.Context, orgID uuid.UUID, sla *models.SlaTracking) error {
	sla.OrgID = orgID
	return r.db.WithContext(ctx).Create(sla).Error
}

func (r *SlaTrackingRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.SlaTracking, error) {
	var sla models.SlaTracking
	err := r.db.WithContext(ctx).Scopes(TenantScope(ctx)).Where("id = ?", id).First(&sla).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrSlaTrackingNotFound
		}
		return nil, err
	}
	return &sla, nil
}

func (r *SlaTrackingRepository) List(ctx context.Context, limit, offset int) ([]models.SlaTracking, error) {
	var slas []models.SlaTracking
	query := r.db.WithContext(ctx).Scopes(TenantScope(ctx)).Order("deadline ASC")
	if limit > 0 {
		query = query.Limit(limit).Offset(offset)
	}
	err := query.Find(&slas).Error
	return slas, err
}

func (r *SlaTrackingRepository) ListPending(ctx context.Context) ([]models.SlaTracking, error) {
	var slas []models.SlaTracking
	err := r.db.WithContext(ctx).
		Scopes(TenantScope(ctx)).
		Where("status = ?", "pending").
		Order("deadline ASC").
		Find(&slas).Error
	return slas, err
}

func (r *SlaTrackingRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status string) error {
	return r.db.WithContext(ctx).Model(&models.SlaTracking{}).
		Scopes(TenantScope(ctx)).
		Where("id = ?", id).
		Update("status", status).Error
}

func (r *SlaTrackingRepository) ExistsByCveAndSbom(ctx context.Context, cve string, sbomID *uuid.UUID) (bool, error) {
	var count int64
	query := r.db.WithContext(ctx).Model(&models.SlaTracking{}).
		Scopes(TenantScope(ctx)).
		Where("cve = ?", cve)
	if sbomID == nil {
		query = query.Where("sbom_id IS NULL")
	} else {
		query = query.Where("sbom_id = ?", *sbomID)
	}
	err := query.Count(&count).Error
	return count > 0, err
}

func (r *SlaTrackingRepository) ListByStatus(ctx context.Context, status string, limit, offset int) ([]models.SlaTracking, error) {
	var slas []models.SlaTracking
	query := r.db.WithContext(ctx).Scopes(TenantScope(ctx)).Where("status = ?", status).Order("deadline ASC")
	if limit > 0 {
		query = query.Limit(limit).Offset(offset)
	}
	err := query.Find(&slas).Error
	return slas, err
}

func (r *SlaTrackingRepository) CountByStatus(ctx context.Context, status string) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&models.SlaTracking{}).
		Scopes(TenantScope(ctx)).
		Where("status = ?", status).
		Count(&count).Error
	return count, err
}

func (r *SlaTrackingRepository) CountAll(ctx context.Context) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&models.SlaTracking{}).
		Scopes(TenantScope(ctx)).
		Count(&count).Error
	return count, err
}

func (r *SlaTrackingRepository) ListApproaching(ctx context.Context, within time.Duration) ([]models.SlaTracking, error) {
	var slas []models.SlaTracking
	deadline := time.Now().Add(within)
	err := r.db.WithContext(ctx).
		Scopes(TenantScope(ctx)).
		Where("deadline <= ? AND status = 'pending'", deadline).
		Order("deadline ASC").
		Find(&slas).Error
	return slas, err
}

func (r *SlaTrackingRepository) CountApproaching(ctx context.Context, within time.Duration) (int64, error) {
	var count int64
	deadline := time.Now().Add(within)
	err := r.db.WithContext(ctx).Model(&models.SlaTracking{}).
		Scopes(TenantScope(ctx)).
		Where("deadline <= ? AND status = 'pending'", deadline).
		Count(&count).Error
	return count, err
}

func (r *SlaTrackingRepository) ListViolated(ctx context.Context) ([]models.SlaTracking, error) {
	var slas []models.SlaTracking
	err := r.db.WithContext(ctx).
		Scopes(TenantScope(ctx)).
		Where("deadline < ? AND status = 'pending'", time.Now()).
		Order("deadline ASC").
		Find(&slas).Error
	return slas, err
}
