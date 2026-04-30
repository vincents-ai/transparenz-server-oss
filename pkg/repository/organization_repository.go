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
	"github.com/transparenz/transparenz-server-oss/pkg/models"
	"gorm.io/gorm"
)

var ErrOrganizationNotFound = errors.New("organization not found")

// OrganizationRepository provides data access for organization records.
type OrganizationRepository struct {
	db *gorm.DB
}

// NewOrganizationRepository creates a new OrganizationRepository backed by the given DB.
func NewOrganizationRepository(db *gorm.DB) *OrganizationRepository {
	return &OrganizationRepository{db: db}
}

func (r *OrganizationRepository) Create(ctx context.Context, org *models.Organization) error {
	return r.db.WithContext(ctx).Create(org).Error
}

func (r *OrganizationRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Organization, error) {
	var org models.Organization
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&org).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrOrganizationNotFound
		}
		return nil, err
	}
	return &org, nil
}

func (r *OrganizationRepository) GetBySlug(ctx context.Context, slug string) (*models.Organization, error) {
	var org models.Organization
	err := r.db.WithContext(ctx).Where("slug = ?", slug).First(&org).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrOrganizationNotFound
		}
		return nil, err
	}
	return &org, nil
}

func (r *OrganizationRepository) Update(ctx context.Context, org *models.Organization) error {
	return r.db.WithContext(ctx).Save(org).Error
}

func (r *OrganizationRepository) Delete(ctx context.Context, id uuid.UUID) error {
	result := r.db.WithContext(ctx).Delete(&models.Organization{}, "id = ?", id)
	if result.RowsAffected == 0 {
		return ErrOrganizationNotFound
	}
	return result.Error
}

func (r *OrganizationRepository) ListAll(ctx context.Context) ([]models.Organization, error) {
	var orgs []models.Organization
	err := r.db.WithContext(ctx).Find(&orgs).Error
	return orgs, err
}

func (r *OrganizationRepository) GetByTier(ctx context.Context, tier string) ([]models.Organization, error) {
	var orgs []models.Organization
	err := r.db.WithContext(ctx).Where("tier = ?", tier).Find(&orgs).Error
	return orgs, err
}

// SupportPeriodStatus holds computed support period metrics for an organization.
type SupportPeriodStatus struct {
	MonthsRemaining     int64
	DaysRemaining       int64
	IsExpired           bool
	PercentageElapsed   float64
	SupportStartDate    *time.Time
	SupportEndDate      *time.Time
	SupportPeriodMonths int
}

func (r *OrganizationRepository) UpdateSupportPeriod(ctx context.Context, orgID uuid.UUID, months int) error {
	now := time.Now().UTC()
	endDate := now.AddDate(0, months, 0)
	return r.db.WithContext(ctx).Model(&models.Organization{}).Where("id = ?", orgID).Updates(map[string]interface{}{
		"support_period_months": months,
		"support_start_date":    now,
		"support_end_date":      endDate,
	}).Error
}

func (r *OrganizationRepository) GetSupportPeriodStatus(ctx context.Context, orgID uuid.UUID) (*SupportPeriodStatus, error) {
	var org models.Organization
	err := r.db.WithContext(ctx).Select("support_period_months, support_start_date, support_end_date").Where("id = ?", orgID).First(&org).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrOrganizationNotFound
		}
		return nil, err
	}

	status := &SupportPeriodStatus{
		SupportPeriodMonths: org.SupportPeriodMonths,
		SupportStartDate:    org.SupportStartDate,
		SupportEndDate:      org.SupportEndDate,
	}

	if org.SupportStartDate == nil || org.SupportEndDate == nil {
		return status, nil
	}

	now := time.Now().UTC()
	if now.After(*org.SupportEndDate) {
		status.IsExpired = true
		status.DaysRemaining = 0
		status.MonthsRemaining = 0
		status.PercentageElapsed = 100.0
		return status, nil
	}

	totalDuration := org.SupportEndDate.Sub(*org.SupportStartDate)
	elapsed := now.Sub(*org.SupportStartDate)
	remaining := org.SupportEndDate.Sub(now)

	status.PercentageElapsed = (elapsed.Seconds() / totalDuration.Seconds()) * 100
	if status.PercentageElapsed < 0 {
		status.PercentageElapsed = 0
	}
	status.DaysRemaining = int64(remaining.Hours() / 24)
	status.MonthsRemaining = int64(remaining.Hours() / (24 * 30))

	return status, nil
}
