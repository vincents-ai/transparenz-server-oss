// SPDX-FileCopyrightText: 2026 Vincent Palmer
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Transparenz, an open-source CRA compliance server.
// It is licensed under the GNU Affero General Public License v3.0; see LICENSE.
package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
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
	return omittingUnsetEntityClass(r.db.WithContext(ctx), org).Create(org).Error
}

// omittingUnsetEntityClass keeps an unclassified organisation insertable.
//
// The column is nullable and CHECK-constrained to 'essential' or 'important'
// (migration 000043), because "not yet classified" is a legitimate state: most
// organisations are created before anyone decides their NIS2 status. The model
// carries the field as a plain string, so GORM sends "" rather than NULL and the
// CHECK rejects it — which made creating an organisation without an entity class
// fail outright against a migrated database. Omitting the column lets the default
// (NULL) apply, and the field still reads back as "".
func omittingUnsetEntityClass(tx *gorm.DB, org *models.Organization) *gorm.DB {
	if org == nil {
		return tx
	}
	// Both NIS2 routing columns are nullable and format-constrained, so "" is not
	// a legal value for either: the migration means "unknown" to be NULL. The
	// model carries them as plain strings, so every field left unset has to be
	// omitted rather than written as an empty string.
	var unset []string
	if org.NIS2EntityClass == "" {
		unset = append(unset, "NIS2EntityClass")
	}
	if org.NIS2MemberState == "" {
		unset = append(unset, "NIS2MemberState")
	}
	if len(unset) == 0 {
		return tx
	}
	return tx.Omit(unset...)
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
	if err := SelfScopeGuard(ctx, org.ID); err != nil {
		return err
	}
	return omittingUnsetEntityClass(r.db.WithContext(ctx), org).Save(org).Error
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

// CountAll returns the total number of organizations.
// Used by the license enforcer to check max_orgs limits.
func (r *OrganizationRepository) CountAll(ctx context.Context) (int, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&models.Organization{}).Count(&count).Error
	return int(count), err
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
	if totalDuration.Seconds() == 0 {
		// months=0 means immediately unsupported
		status.PercentageElapsed = 100.0
		status.MonthsRemaining = 0
		status.DaysRemaining = 0
		return status, nil
	}
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
