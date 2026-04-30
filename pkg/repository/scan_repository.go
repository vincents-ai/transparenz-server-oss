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

var ErrScanNotFound = errors.New("scan not found")

// ScanRepository provides data access for vulnerability scans.
type ScanRepository struct {
	db *gorm.DB
}

// NewScanRepository creates a new ScanRepository backed by the given DB.
func NewScanRepository(db *gorm.DB) *ScanRepository {
	return &ScanRepository{db: db}
}

func (r *ScanRepository) Create(ctx context.Context, orgID uuid.UUID, scan *models.Scan) error {
	scan.OrgID = orgID
	return r.db.WithContext(ctx).Create(scan).Error
}

func (r *ScanRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Scan, error) {
	var scan models.Scan
	err := r.db.WithContext(ctx).Scopes(TenantScope(ctx)).Where("id = ?", id).First(&scan).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrScanNotFound
		}
		return nil, err
	}
	return &scan, nil
}

func (r *ScanRepository) Count(ctx context.Context) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&models.Scan{}).
		Scopes(TenantScope(ctx)).
		Count(&count).Error
	return count, err
}

func (r *ScanRepository) List(ctx context.Context, limit, offset int) ([]models.Scan, error) {
	var scans []models.Scan
	query := r.db.WithContext(ctx).Scopes(TenantScope(ctx)).Order("scan_date DESC")
	if limit > 0 {
		query = query.Limit(limit).Offset(offset)
	}
	err := query.Find(&scans).Error
	return scans, err
}

func (r *ScanRepository) ListBySbomID(ctx context.Context, sbomID uuid.UUID, limit, offset int) ([]models.Scan, error) {
	var scans []models.Scan
	query := r.db.WithContext(ctx).Scopes(TenantScope(ctx)).Where("sbom_id = ?", sbomID).Order("scan_date DESC")
	if limit > 0 {
		query = query.Limit(limit).Offset(offset)
	}
	err := query.Find(&scans).Error
	return scans, err
}

// Cross-tenant: intentionally called from background workers without tenant context.
func (r *ScanRepository) ListPending(ctx context.Context, limit int) ([]models.Scan, error) {
	var scans []models.Scan
	err := r.db.WithContext(ctx).
		Where("status = ?", "pending").
		Order("created_at ASC").
		Limit(limit).
		Find(&scans).Error
	return scans, err
}

func (r *ScanRepository) Update(ctx context.Context, scan *models.Scan) error {
	return r.db.WithContext(ctx).
		Scopes(TenantScope(ctx)).
		Where("id = ?", scan.ID).
		Save(scan).Error
}

func (r *ScanRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status string) error {
	return r.db.WithContext(ctx).
		Model(&models.Scan{}).
		Scopes(TenantScope(ctx)).
		Where("id = ?", id).
		Update("status", status).Error
}
