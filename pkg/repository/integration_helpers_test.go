// SPDX-FileCopyrightText: 2026 Vincent Palmer
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Transparenz, an open-source CRA compliance server.
// It is licensed under the GNU Affero General Public License v3.0; see LICENSE.

//go:build integration

package repository

import (
	"os"
	"testing"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// setupTenantTestDB returns a PostgreSQL connection for integration tests.
//
// This helper was referenced by tenant_schema_integration_test.go but never
// defined, so `go vet -tags integration ./pkg/repository` did not compile and no
// integration test in this package could be run. It is defined here because its
// callers need exactly one thing: a *gorm.DB. Each test that needs particular
// tables creates them itself.
func setupTenantTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	return integrationDB(t)
}

// integrationDB is the shared connector, skipping when no database is
// configured rather than failing, so a developer without a local Postgres is
// not blocked from running the unit suite.
func integrationDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is not set; skipping PostgreSQL integration test")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("connect to %s: %v", dsn, err)
	}
	return db
}
