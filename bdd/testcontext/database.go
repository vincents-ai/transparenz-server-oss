// Copyright (c) 2026 Vincent Palmer. Licensed under AGPL-3.0.
package testcontext

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vincents-ai/transparenz-server-oss/internal/config"
	"gorm.io/gorm"
)

func InitDatabase(ctx context.Context, dsn string) (*gorm.DB, error) {
	db, err := config.InitDB(dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	if err := db.Exec("DROP SCHEMA IF EXISTS compliance CASCADE").Error; err != nil {
		return nil, fmt.Errorf("failed to drop schema: %w", err)
	}
	if err := db.Exec("CREATE SCHEMA compliance").Error; err != nil {
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}

	migrationsDir := filepath.Join("..", "migrations")
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read migrations directory: %w", err)
	}

	var upFiles []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".up.sql") {
			upFiles = append(upFiles, name)
		}
	}
	sort.Strings(upFiles)

	for _, file := range upFiles {
		content, err := os.ReadFile(filepath.Join(migrationsDir, file)) //nolint:gosec
		if err != nil {
			return nil, fmt.Errorf("failed to read migration %s: %w", file, err)
		}

		if err := db.WithContext(ctx).Exec(string(content)).Error; err != nil {
			return nil, fmt.Errorf("failed to execute migration %s: %w", file, err)
		}
	}

	return db, nil
}
