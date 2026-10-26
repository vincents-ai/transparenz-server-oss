// SPDX-FileCopyrightText: 2026 Vincent Palmer
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Transparenz, an open-source CRA compliance server.
// It is licensed under the GNU Affero General Public License v3.0; see LICENSE.

//go:build integration

package repository

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// An organisation provisioned by one release must receive the migrations of the
// next. Before per-schema version tracking there was no upgrade path at all: every
// provisioning call replayed the whole sequence, which only worked because a new
// schema starts empty — so an existing tenant's schema was whatever it was created
// with, for ever. A release that adds a column (this one does) would silently leave
// every existing schema behind, and the failure would surface as a 500 on the first
// request that touched the new column.
func TestSchemaPerOrg_ExistingSchemaReceivesNewMigrations(t *testing.T) {
	db := setupTenantTestDB(t)
	baseDSN := os.Getenv("DATABASE_URL")

	dir := t.TempDir()
	writeMigration := func(name, sql string) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(sql), 0o600))
	}

	// Release 1.
	writeMigration("000002_first.up.sql", "CREATE TABLE notes (id UUID PRIMARY KEY, body TEXT);")

	newBackend := func() *SchemaPerOrgBackend {
		b := NewSchemaPerOrgBackend(db, dir, baseDSN)
		b.logger = zap.NewNop()
		return b
	}

	orgID := uuid.New()
	schemaName := fmt.Sprintf("compliance_%s", orgID.String())

	first, err := newBackend().getOrCreateOrgDB(context.Background(), orgID)
	require.NoError(t, err)
	require.NoError(t, first.Exec(`INSERT INTO notes (id, body) VALUES (?, ?)`,
		uuid.New(), "written by release 1").Error)

	var haveNewColumn bool
	require.NoError(t, first.Raw(`SELECT EXISTS (
		SELECT 1 FROM information_schema.columns
		WHERE table_schema = ? AND table_name = 'notes' AND column_name = 'pinned'
	)`, schemaName).Scan(&haveNewColumn).Error)
	require.False(t, haveNewColumn, "release 1 does not have the new column")

	// Release 2 adds a column. A new backend instance stands in for a restarted
	// server, so the cached pool from the first provisioning is not reused.
	writeMigration("000003_add_pinned.up.sql", "ALTER TABLE notes ADD COLUMN pinned BOOLEAN NOT NULL DEFAULT FALSE;")

	second, err := newBackend().getOrCreateOrgDB(context.Background(), orgID)
	require.NoError(t, err, "an existing schema must be upgraded, not replayed from the start")

	require.NoError(t, second.Raw(`SELECT EXISTS (
		SELECT 1 FROM information_schema.columns
		WHERE table_schema = ? AND table_name = 'notes' AND column_name = 'pinned'
	)`, schemaName).Scan(&haveNewColumn).Error)
	assert.True(t, haveNewColumn, "the new column must exist after the upgrade")

	// The organisation's data survives the upgrade, and the versions are recorded.
	var body string
	require.NoError(t, second.Raw(`SELECT body FROM notes LIMIT 1`).Scan(&body).Error)
	assert.Equal(t, "written by release 1", body)

	var applied int64
	require.NoError(t, second.Raw(`SELECT COUNT(*) FROM schema_migrations`).Scan(&applied).Error)
	assert.EqualValues(t, 2, applied, "both migrations are recorded as applied")

	// Re-provisioning again is a no-op rather than a replay.
	third, err := newBackend().getOrCreateOrgDB(context.Background(), orgID)
	require.NoError(t, err, "a third provisioning must not re-run applied migrations")
	require.NoError(t, third.Raw(`SELECT COUNT(*) FROM schema_migrations`).Scan(&applied).Error)
	assert.EqualValues(t, 2, applied)
}
