// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/transparenz/transparenz-server-oss/pkg/middleware"
	"gorm.io/gorm"
)

// TenantScope automatically appends org_id constraint to queries.
// Works with both StandardBackend (row-level isolation) and SchemaPerOrgBackend
// (schema-per-org isolation) via the shared middleware context.
// Failsafe: if no org context found, forces query to return no results.
func TenantScope(ctx context.Context) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		orgID, err := middleware.GetOrgIDFromContext(ctx)
		if err == nil && orgID != "" {
			parsed, err := uuid.Parse(orgID)
			if err == nil {
				return db.Where("org_id = ?", parsed)
			}
		}
		return db.Where("1 = 0")
	}
}

// tenantScopeThroughParent returns a scope that filters records belonging to the
// current tenant by checking that a foreign key references a row in a parent table
// whose org_id matches the one in ctx. This is used for child tables that lack their
// own org_id column but inherit tenant membership from a parent entity.
// Failsafe: if no org context found, forces query to return no results (WHERE 1=0).
func tenantScopeThroughParent(ctx context.Context, parentTable, foreignKey string) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		orgID, err := middleware.GetOrgIDFromContext(ctx)
		if err == nil && orgID != "" {
			parsed, err := uuid.Parse(orgID)
			if err == nil {
				return db.Where(
					foreignKey+" IN (SELECT id FROM "+parentTable+" WHERE org_id = ?)",
					parsed,
				)
			}
		}
		return db.Where("1 = 0")
	}
}
