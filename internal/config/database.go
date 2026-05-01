// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
// Package config provides database configuration and connection management
// for the transparenz-server application.
package config

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/viper"
	"github.com/vincents-ai/transparenz-server-oss/pkg/repository"
	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// TenantBackend is created in main.go after InitDB when org tier is known.
// Use repository.NewTenantBackend(db, tier) to get the appropriate backend.
//
// InitDB initializes a new database connection using GORM with PostgreSQL.
// It ensures the search_path is set to 'compliance' schema.
//
// Parameters:
//   - databaseURL: PostgreSQL connection string (e.g., "postgres://user:pass@host:port/dbname")
//
// Returns:
//   - *gorm.DB: GORM database instance
//   - error: Any error encountered during connection
func InitDB(databaseURL string) (*gorm.DB, error) {
	// Append search_path=compliance if not already present
	dsn := databaseURL
	if !strings.Contains(databaseURL, "search_path") {
		separator := "?"
		if strings.Contains(databaseURL, "?") {
			separator = "&"
		}
		dsn = fmt.Sprintf("%s%ssearch_path=compliance", databaseURL, separator)
	}

	// Open GORM connection with PostgreSQL driver
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	// Test the connection
	if err := db.Exec("SELECT 1").Error; err != nil {
		return nil, fmt.Errorf("failed to verify database connection: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}
	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetConnMaxLifetime(5 * time.Minute)

	return db, nil
}

// CheckDBHealth verifies the database connection is alive and responsive.
// This function is useful for health check endpoints.
//
// Parameters:
//   - db: GORM database instance to check
//
// Returns:
//   - error: nil if connection is healthy, error otherwise
func CheckDBHealth(db *gorm.DB) error {
	if err := db.Exec("SELECT 1").Error; err != nil {
		return fmt.Errorf("database health check failed: %w", err)
	}
	return nil
}

func parseInstanceDSNs(raw string) (map[string]string, error) {
	if raw == "" {
		return nil, nil
	}
	var dsns map[string]string
	if err := json.Unmarshal([]byte(raw), &dsns); err != nil {
		return nil, fmt.Errorf("parse INSTANCE_DSNS: %w", err)
	}
	return dsns, nil
}

func InitMultiTenantDB(cfg *Config) (*gorm.DB, repository.TenantBackend, error) {
	switch cfg.MultiTenantMode {
	case "instance_per_org":
		return initInstancePerOrgDB(cfg)
	case "schema_per_org":
		db, err := InitDB(cfg.DatabaseURL)
		if err != nil {
			return nil, nil, err
		}
		return db, repository.NewSchemaPerOrgBackend(db, "./migrations", cfg.DatabaseURL), nil
	default:
		db, err := InitDB(cfg.DatabaseURL)
		if err != nil {
			return nil, nil, err
		}
		return db, repository.NewStandardBackend(db), nil
	}
}

func initInstancePerOrgDB(cfg *Config) (*gorm.DB, repository.TenantBackend, error) {
	db, err := InitDB(cfg.DatabaseURL)
	if err != nil {
		return nil, nil, err
	}

	dsns, err := parseInstanceDSNs(viper.GetString("INSTANCE_DSNS"))
	if err != nil {
		return nil, nil, err
	}

	logger, _ := zap.NewProduction()
	backend := repository.NewInstancePerOrgBackend(logger)

	ctx := context.Background()
	for orgIDStr, dsn := range dsns {
		orgID, err := uuid.Parse(orgIDStr)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid org ID in INSTANCE_DSNS: %s: %w", orgIDStr, err)
		}
		if err := backend.Provision(ctx, orgID, dsn); err != nil {
			return nil, nil, fmt.Errorf("provision instance for org %s: %w", orgIDStr, err)
		}
	}

	return db, backend, nil
}
