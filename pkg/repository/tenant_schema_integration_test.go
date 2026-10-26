//go:build integration

// This file had stopped compiling: it called NewSchemaPerOrgBackend with two
// arguments after the constructor gained a base DSN, and indexed b.schemas as a
// map after it became a sync.Map. Nothing caught it because no CI job builds the
// integration-tagged tests in this package — the only integration job targets
// ./tests/integration. A test file that does not compile is not a test.

package repository

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSchemaPerOrgBackend_TracksSchemas(t *testing.T) {
	db := setupTenantTestDB(t)
	b := NewSchemaPerOrgBackend(db, "", os.Getenv("DATABASE_URL"))
	orgID := uuid.New()
	ctx := context.Background()

	t.Run("CreateOrgSchema tracks the org", func(t *testing.T) {
		require.NoError(t, b.CreateOrgSchema(ctx, orgID))
		_, tracked := b.schemas.Load(orgID)
		assert.True(t, tracked)
	})

	t.Run("DropOrgSchema removes the org", func(t *testing.T) {
		_ = b.DropOrgSchema(ctx, orgID)
		_, tracked := b.schemas.Load(orgID)
		assert.False(t, tracked)
	})

	t.Run("GetDB returns the same db instance", func(t *testing.T) {
		assert.Equal(t, db, b.GetDB())
	})

	t.Run("SetOrgContext returns context with org", func(t *testing.T) {
		ctx := b.SetOrgContext(ctx, orgID)
		assert.NotNil(t, ctx)
	})
}
