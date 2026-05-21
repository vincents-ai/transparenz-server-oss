package repository

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupTenantTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	return db
}

func TestNewTenantBackend_Factory(t *testing.T) {
	db := setupTenantTestDB(t)

	t.Run("standard tier returns StandardBackend", func(t *testing.T) {
		b := NewTenantBackend(db, "standard", "", "")
		_, ok := b.(*StandardBackend)
		assert.True(t, ok)
	})

	t.Run("enterprise tier returns StandardBackend", func(t *testing.T) {
		b := NewTenantBackend(db, "enterprise", "", "")
		_, ok := b.(*StandardBackend)
		assert.True(t, ok)
	})

	t.Run("sovereign tier returns SchemaPerOrgBackend", func(t *testing.T) {
		b := NewTenantBackend(db, "sovereign", "", "")
		_, ok := b.(*SchemaPerOrgBackend)
		assert.True(t, ok)
	})

	t.Run("unknown tier returns StandardBackend", func(t *testing.T) {
		b := NewTenantBackend(db, "unknown", "", "")
		_, ok := b.(*StandardBackend)
		assert.True(t, ok)
	})

	t.Run("empty tier returns StandardBackend", func(t *testing.T) {
		b := NewTenantBackend(db, "", "", "")
		_, ok := b.(*StandardBackend)
		assert.True(t, ok)
	})

	t.Run("all backends implement TenantBackend interface", func(t *testing.T) {
		var _ TenantBackend = NewStandardBackend(db)
		var _ TenantBackend = NewSchemaPerOrgBackend(db, "", "")
	})
}

func TestStandardBackend_SchemaNoOps(t *testing.T) {
	db := setupTenantTestDB(t)
	b := NewStandardBackend(db)
	orgID := uuid.New()
	ctx := context.Background()

	t.Run("CreateOrgSchema returns nil", func(t *testing.T) {
		err := b.CreateOrgSchema(ctx, orgID)
		assert.NoError(t, err)
	})

	t.Run("DropOrgSchema returns nil", func(t *testing.T) {
		err := b.DropOrgSchema(ctx, orgID)
		assert.NoError(t, err)
	})

	t.Run("SetOrgContext returns context with org", func(t *testing.T) {
		ctx := b.SetOrgContext(ctx, orgID)
		assert.NotNil(t, ctx)
	})

	t.Run("GetDB returns the same db instance", func(t *testing.T) {
		assert.Equal(t, db, b.GetDB())
	})
}

func TestTenantBackend_Interface(t *testing.T) {
	db := setupTenantTestDB(t)
	orgID := uuid.New()
	ctx := context.Background()

	t.Run("StandardBackend satisfies interface", func(t *testing.T) {
		var b TenantBackend = NewStandardBackend(db)
		_ = b.SetOrgContext(ctx, orgID)
		assert.NotNil(t, b.GetDB())
		assert.NoError(t, b.CreateOrgSchema(ctx, orgID))
		assert.NoError(t, b.DropOrgSchema(ctx, orgID))
	})

	t.Run("SchemaPerOrgBackend satisfies interface", func(t *testing.T) {
		var b TenantBackend = NewSchemaPerOrgBackend(db, "", "")
		_ = b.SetOrgContext(ctx, orgID)
		assert.NotNil(t, b.GetDB())
	})
}
