// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package repository

import (
	"context"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/transparenz/transparenz-server-oss/pkg/models"
)

// VexStatementRepository provides data access for VEX statements.
type VexStatementRepository struct {
	db *gorm.DB
}

// NewVexStatementRepository creates a new VexStatementRepository backed by the given DB.
func NewVexStatementRepository(db *gorm.DB) *VexStatementRepository {
	return &VexStatementRepository{db: db}
}

func (r *VexStatementRepository) Create(ctx context.Context, orgID uuid.UUID, stmt *models.VexStatement) error {
	stmt.OrgID = orgID
	return r.db.WithContext(ctx).Create(stmt).Error
}

func (r *VexStatementRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.VexStatement, error) {
	var stmt models.VexStatement
	err := r.db.WithContext(ctx).Scopes(TenantScope(ctx)).First(&stmt, "id = ?", id).Error
	if err != nil {
		return nil, err
	}
	return &stmt, nil
}

func (r *VexStatementRepository) CountByOrg(ctx context.Context, orgID uuid.UUID) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&models.VexStatement{}).
		Where("org_id = ?", orgID).
		Count(&count).Error
	return count, err
}

func (r *VexStatementRepository) ListByOrg(ctx context.Context, orgID uuid.UUID, limit, offset int) ([]models.VexStatement, error) {
	var stmts []models.VexStatement
	query := r.db.WithContext(ctx).Where("org_id = ?", orgID).Order("created_at DESC")
	if limit > 0 {
		query = query.Limit(limit).Offset(offset)
	}
	err := query.Find(&stmts).Error
	return stmts, err
}

func (r *VexStatementRepository) ListActiveByOrg(ctx context.Context, orgID uuid.UUID) ([]models.VexStatement, error) {
	var stmts []models.VexStatement
	err := r.db.WithContext(ctx).Where("org_id = ? AND status = ?", orgID, "active").Order("created_at DESC").Find(&stmts).Error
	return stmts, err
}

func (r *VexStatementRepository) ListByCVE(ctx context.Context, orgID uuid.UUID, cve string) ([]models.VexStatement, error) {
	var stmts []models.VexStatement
	err := r.db.WithContext(ctx).Where("org_id = ? AND cve = ? AND status = ?", orgID, cve, "active").Order("created_at DESC").Find(&stmts).Error
	return stmts, err
}

func (r *VexStatementRepository) Update(ctx context.Context, stmt *models.VexStatement) error {
	return r.db.WithContext(ctx).Scopes(TenantScope(ctx)).Save(stmt).Error
}

// Cross-tenant: intentionally called from background workers without tenant context.
func (r *VexStatementRepository) ListExpired(ctx context.Context) ([]models.VexStatement, error) {
	var stmts []models.VexStatement
	err := r.db.WithContext(ctx).Where("status = ? AND valid_until IS NOT NULL AND valid_until < NOW()", "active").Find(&stmts).Error
	return stmts, err
}
