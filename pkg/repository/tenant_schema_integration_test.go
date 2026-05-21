//go:build integration

package repository

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestSchemaPerOrgBackend_TracksSchemas(t *testing.T) {
	db := setupTenantTestDB(t)
	b := NewSchemaPerOrgBackend(db, "")
	orgID := uuid.New()
	ctx := context.Background()

	t.Run("CreateOrgSchema tracks the org", func(t *testing.T) {
		_ = b.CreateOrgSchema(ctx, orgID)
		assert.Contains(t, b.schemas, orgID)
		assert.True(t, b.schemas[orgID])
	})

	t.Run("DropOrgSchema removes the org", func(t *testing.T) {
		_ = b.DropOrgSchema(ctx, orgID)
		_, exists := b.schemas[orgID]
		assert.False(t, exists)
	})

	t.Run("GetDB returns the same db instance", func(t *testing.T) {
		assert.Equal(t, db, b.GetDB())
	})

	t.Run("SetOrgContext returns context with org", func(t *testing.T) {
		ctx := b.SetOrgContext(ctx, orgID)
		assert.NotNil(t, ctx)
	})
}
