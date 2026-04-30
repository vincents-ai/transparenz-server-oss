// Copyright (c) 2026 Vincent Palmer. Licensed under AGPL-3.0.
package testcontext

import (
	"github.com/google/uuid"
	"github.com/transparenz/transparenz-server-oss/internal/models"
	"gorm.io/gorm"
)

func SeedOrganization(db *gorm.DB, org models.Organization) error {
	return db.Create(&org).Error
}

func SeedTestOrg(db *gorm.DB) (models.Organization, error) {
	orgID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")

	org := models.Organization{
		ID:                  orgID,
		Name:                "Test Corp",
		Slug:                "test-corp",
		Tier:                "enterprise",
		EnisaSubmissionMode: "export",
		CsafScope:           "per_sbom",
		PdfTemplate:         "generic",
		SlaTrackingMode:     "per_cve",
		SlaMode:             "fully_automatic",
	}

	err := db.Where("id = ?", orgID).FirstOrCreate(&org).Error
	if err != nil {
		return models.Organization{}, err
	}

	return org, nil
}
