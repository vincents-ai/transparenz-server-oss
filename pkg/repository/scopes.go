// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package repository

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/vincents-ai/transparenz-server-oss/pkg/middleware"
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

// SelfScopeGuard checks that the organization ID from the context matches the
// given record's owning org ID. Use this for update/delete operations on repositories
// where the record's primary key might not match the authenticated tenant.
//
// Returns an error if the context org ID differs from the record's org ID.
// Returns nil if they match or if no org context is available (allows admin-level
// callers that bypass tenant context).
//
// Usage:
//
//	if err := SelfScopeGuard(ctx, record.OrgID); err != nil {
//	    return err
//	}
func SelfScopeGuard(ctx context.Context, recordOrgID uuid.UUID) error {
	orgID, err := middleware.GetOrgIDFromContext(ctx)
	if err != nil || orgID == "" {
		return nil // no tenant context — admin-level access
	}
	parsed, parseErr := uuid.Parse(orgID)
	if parseErr != nil {
		return nil
	}
	if parsed != recordOrgID {
		return fmt.Errorf("self-scope violation: cannot operate on record owned by org %s under context of org %s", recordOrgID, parsed)
	}
	return nil
}
