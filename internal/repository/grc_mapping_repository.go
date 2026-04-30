// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/transparenz/transparenz-server-oss/internal/models"
	"gorm.io/gorm"
)

type GRCMappingRepository struct {
	db *gorm.DB
}

func NewGRCMappingRepository(db *gorm.DB) *GRCMappingRepository {
	return &GRCMappingRepository{db: db}
}

func (r *GRCMappingRepository) CreateBatch(ctx context.Context, mappings []models.GRCMapping) error {
	if len(mappings) == 0 {
		return nil
	}
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return tx.CreateInBatches(mappings, 100).Error
	})
}

func (r *GRCMappingRepository) ListByVulnerability(ctx context.Context, orgID uuid.UUID, vulnID string) ([]models.GRCMapping, error) {
	var mappings []models.GRCMapping
	err := r.db.WithContext(ctx).
		Scopes(TenantScope(ctx)).
		Where("vulnerability_id IN (SELECT id FROM compliance.vulnerabilities WHERE cve = ? AND org_id = ?)", vulnID, orgID).
		Find(&mappings).Error
	return mappings, err
}

func (r *GRCMappingRepository) ListByVulnerabilityID(ctx context.Context, vulnID uuid.UUID) ([]models.GRCMapping, error) {
	var mappings []models.GRCMapping
	err := r.db.WithContext(ctx).
		Scopes(TenantScope(ctx)).
		Where("vulnerability_id = ?", vulnID).
		Find(&mappings).Error
	return mappings, err
}

func (r *GRCMappingRepository) ListByVulnerabilityIDs(ctx context.Context, vulnIDs []uuid.UUID) ([]models.GRCMapping, error) {
	if len(vulnIDs) == 0 {
		return nil, nil
	}
	var mappings []models.GRCMapping
	err := r.db.WithContext(ctx).
		Scopes(TenantScope(ctx)).
		Where("vulnerability_id IN ?", vulnIDs).
		Find(&mappings).Error
	return mappings, err
}

func (r *GRCMappingRepository) DeleteByVulnerability(ctx context.Context, orgID uuid.UUID, vulnID string) error {
	var vuln models.Vulnerability
	if err := r.db.WithContext(ctx).
		Scopes(TenantScope(ctx)).
		Where("cve = ? AND org_id = ?", vulnID, orgID).
		First(&vuln).Error; err != nil {
		return err
	}
	return r.db.WithContext(ctx).
		Scopes(TenantScope(ctx)).
		Where("vulnerability_id = ?", vuln.ID).
		Delete(&models.GRCMapping{}).Error
}

func (r *GRCMappingRepository) ListByOrg(ctx context.Context, orgID uuid.UUID) ([]models.GRCMapping, error) {
	var mappings []models.GRCMapping
	err := r.db.WithContext(ctx).
		Scopes(TenantScope(ctx)).
		Preload("Vulnerability").
		Where("org_id = ?", orgID).
		Find(&mappings).Error
	return mappings, err
}

func (r *GRCMappingRepository) CountByFramework(ctx context.Context, orgID uuid.UUID) (map[string]int64, error) {
	type result struct {
		Framework string
		Count     int64
	}
	var results []result
	err := r.db.WithContext(ctx).
		Scopes(TenantScope(ctx)).
		Model(&models.GRCMapping{}).
		Select("framework, COUNT(*) as count").
		Where("org_id = ?", orgID).
		Group("framework").
		Scan(&results).Error
	if err != nil {
		return nil, err
	}
	counts := make(map[string]int64, len(results))
	for _, r := range results {
		counts[r.Framework] = r.Count
	}
	return counts, nil
}

func (r *GRCMappingRepository) CountDistinctVulnsWithMappings(ctx context.Context, orgID uuid.UUID) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).
		Scopes(TenantScope(ctx)).
		Model(&models.GRCMapping{}).
		Where("org_id = ? AND vulnerability_id IS NOT NULL", orgID).
		Distinct("vulnerability_id").
		Count(&count).Error
	return count, err
}
