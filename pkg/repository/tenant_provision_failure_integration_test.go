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

// Provisioning is part of the security boundary, so a failed attempt must not
// leave a half-built schema behind. It used to: the migration loop returned on
// error without dropping what it had created, and the next attempt found the
// schema (CREATE SCHEMA IF NOT EXISTS) and re-ran every migration from the start
// against objects that already existed — turning a transient failure into a
// permanently broken organisation.
func TestSchemaPerOrg_ProvisionFailureLeavesNoSchemaBehind(t *testing.T) {
	db := setupTenantTestDB(t)

	// A migration directory that always fails on its second statement.
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "000002_ok.up.sql"),
		[]byte("CREATE TABLE ok_table (id UUID PRIMARY KEY);"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "000003_broken.up.sql"),
		[]byte("CREATE TABLE broken_table (this is not sql);"), 0o600))

	b := NewSchemaPerOrgBackend(db, dir, os.Getenv("DATABASE_URL"))
	// The constructor builds its own logger; replace it so the expected failure
	// does not print an error-level line as though the suite were broken.
	b.logger = zap.NewNop()

	orgID := uuid.New()
	schemaName := fmt.Sprintf("compliance_%s", orgID.String())

	_, err := b.getOrCreateOrgDB(context.Background(), orgID)
	require.Error(t, err, "a failing migration must fail provisioning")
	assert.Contains(t, err.Error(), "000003_broken")

	var exists bool
	require.NoError(t, db.Raw(
		`SELECT EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = ?)`,
		schemaName).Scan(&exists).Error)
	assert.False(t, exists,
		"the partially migrated schema must be dropped, or the next attempt will "+
			"re-run migrations against objects that already exist and can never recover")
}
