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

var ErrTelemetryConfigNotFound = errors.New("telemetry config not found")

// TelemetryRepository provides data access for organization telemetry configs.
type TelemetryRepository struct {
	db *gorm.DB
}

// NewTelemetryRepository creates a new TelemetryRepository backed by the given DB.
func NewTelemetryRepository(db *gorm.DB) *TelemetryRepository {
	return &TelemetryRepository{db: db}
}

func (r *TelemetryRepository) Create(ctx context.Context, orgID uuid.UUID, config *models.OrgTelemetryConfig) error {
	config.OrgID = orgID
	return r.db.WithContext(ctx).Create(config).Error
}

func (r *TelemetryRepository) GetByOrgID(ctx context.Context, orgID uuid.UUID) (*models.OrgTelemetryConfig, error) {
	var config models.OrgTelemetryConfig
	err := r.db.WithContext(ctx).Where("org_id = ?", orgID).First(&config).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrTelemetryConfigNotFound
		}
		return nil, err
	}
	return &config, nil
}

func (r *TelemetryRepository) Update(ctx context.Context, config *models.OrgTelemetryConfig) error {
	return r.db.WithContext(ctx).Save(config).Error
}

func (r *TelemetryRepository) GetAllActive(ctx context.Context) ([]*models.OrgTelemetryConfig, error) {
	var configs []*models.OrgTelemetryConfig
	err := r.db.WithContext(ctx).Where("active = true").Find(&configs).Error
	if err != nil {
		return nil, err
	}
	return configs, nil
}

func (r *TelemetryRepository) GetByMetricsTokenPrefix(ctx context.Context, prefix string) ([]*models.OrgTelemetryConfig, error) {
	var configs []*models.OrgTelemetryConfig
	err := r.db.WithContext(ctx).Where("metrics_token_prefix = ? AND active = true", prefix).Find(&configs).Error
	if err != nil {
		return nil, err
	}
	return configs, nil
}
