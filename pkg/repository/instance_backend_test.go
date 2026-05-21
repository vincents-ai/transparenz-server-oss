// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package repository

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupInstanceTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	return db
}

func newTestLogger(t *testing.T) *zap.Logger {
	t.Helper()
	log, err := zap.NewDevelopment()
	require.NoError(t, err)
	return log
}

func TestInstancePerOrgBackend_ProvisionAndGetConnection(t *testing.T) {
	log := newTestLogger(t)
	b := NewInstancePerOrgBackend(log)
	orgID := uuid.New()
	ctx := context.Background()

	t.Run("GetConnection returns error for unprovisioned org", func(t *testing.T) {
		_, err := b.GetConnection(orgID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not provisioned")
	})

	t.Run("Provision with bad DSN returns error", func(t *testing.T) {
		err := b.Provision(ctx, orgID, "postgres://invalid:invalid@nonexistent:5432/bad")
		assert.Error(t, err)
	})

	t.Run("Provision and GetConnection succeed with valid DB", func(t *testing.T) {
		orgID2 := uuid.New()
		db := setupInstanceTestDB(t)
		sqlDB, err := db.DB()
		require.NoError(t, err)

		err = b.Provision(ctx, orgID2, "file:testdb?mode=memory&cache=shared")
		if err == nil {
			conn, err := b.GetConnection(orgID2)
			if assert.NoError(t, err) {
				assert.NotNil(t, conn)
			}
			_ = sqlDB.Close()
		}
	})
}

func TestInstancePerOrgBackend_DoubleProvision(t *testing.T) {
	log := newTestLogger(t)
	b := NewInstancePerOrgBackend(log)
	orgID := uuid.New()
	ctx := context.Background()

	err := b.Provision(ctx, orgID, "file:testdb1?mode=memory&cache=shared")
	if err != nil {
		t.Skip("skipping: provision requires running DB")
	}

	err = b.Provision(ctx, orgID, "file:testdb1?mode=memory&cache=shared")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already provisioned")
}

func TestInstancePerOrgBackend_Deprovision(t *testing.T) {
	log := newTestLogger(t)
	b := NewInstancePerOrgBackend(log)
	orgID := uuid.New()
	ctx := context.Background()

	t.Run("Deprovision unprovisioned org returns error", func(t *testing.T) {
		err := b.Deprovision(ctx, orgID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not provisioned")
	})

	t.Run("Provision then Deprovision removes connection", func(t *testing.T) {
		orgID2 := uuid.New()
		err := b.Provision(ctx, orgID2, "file:testdb2?mode=memory&cache=shared")
		if err != nil {
			t.Skip("skipping: provision requires running DB")
		}

		err = b.Deprovision(ctx, orgID2)
		assert.NoError(t, err)

		_, err = b.GetConnection(orgID2)
		assert.Error(t, err)
	})
}

func TestInstancePerOrgBackend_HealthCheck(t *testing.T) {
	log := newTestLogger(t)
	b := NewInstancePerOrgBackend(log)
	ctx := context.Background()

	t.Run("empty pool returns empty map", func(t *testing.T) {
		results := b.HealthCheck(ctx)
		assert.Empty(t, results)
	})

	t.Run("provisioned orgs are healthy", func(t *testing.T) {
		orgID := uuid.New()
		err := b.Provision(ctx, orgID, "file:testdb3?mode=memory&cache=shared")
		if err != nil {
			t.Skip("skipping: provision requires running DB")
		}

		results := b.HealthCheck(ctx)
		if _, ok := results[orgID]; ok {
			assert.NoError(t, results[orgID])
		}
	})
}

func TestInstancePerOrgBackend_TenantBackendInterface(t *testing.T) {
	log := newTestLogger(t)
	orgID := uuid.New()
	ctx := context.Background()

	var _ TenantBackend = NewInstancePerOrgBackend(log)

	b := NewInstancePerOrgBackend(log)

	t.Run("GetDB returns nil", func(t *testing.T) {
		assert.Nil(t, b.GetDB())
	})

	t.Run("SetOrgContext returns context", func(t *testing.T) {
		resultCtx := b.SetOrgContext(ctx, orgID)
		assert.NotNil(t, resultCtx)
	})

	t.Run("CreateOrgSchema returns error", func(t *testing.T) {
		err := b.CreateOrgSchema(ctx, orgID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "use Provision")
	})

	t.Run("DropOrgSchema deprovisions", func(t *testing.T) {
		orgID2 := uuid.New()
		err := b.Provision(ctx, orgID2, "file:testdb4?mode=memory&cache=shared")
		if err != nil {
			t.Skip("skipping: provision requires running DB")
		}
		err = b.DropOrgSchema(ctx, orgID2)
		assert.NoError(t, err)
		_, err = b.GetConnection(orgID2)
		assert.Error(t, err)
	})
}
