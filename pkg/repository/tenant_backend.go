package repository

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type TenantBackend interface {
	SetOrgContext(ctx context.Context, orgID uuid.UUID) context.Context
	GetDB() *gorm.DB
	CreateOrgSchema(ctx context.Context, orgID uuid.UUID) error
	DropOrgSchema(ctx context.Context, orgID uuid.UUID) error
}

type StandardBackend struct {
	db *gorm.DB
}

func NewStandardBackend(db *gorm.DB) *StandardBackend {
	return &StandardBackend{db: db}
}

func (b *StandardBackend) SetOrgContext(ctx context.Context, orgID uuid.UUID) context.Context {
	return context.WithValue(ctx, orgKey(orgID), orgID.String())
}

func (b *StandardBackend) GetDB() *gorm.DB {
	return b.db
}

func (b *StandardBackend) CreateOrgSchema(ctx context.Context, orgID uuid.UUID) error {
	return nil
}

func (b *StandardBackend) DropOrgSchema(ctx context.Context, orgID uuid.UUID) error {
	return nil
}

type SchemaPerOrgBackend struct {
	db           *gorm.DB
	baseDSN      string // base DSN used to create per-org connection pools
	migrationDir string
	schemas      sync.Map // map[uuid.UUID]*gorm.DB — per-org DB with dedicated connection pool
	mu           sync.Mutex
	logger       *zap.Logger
}

func NewSchemaPerOrgBackend(db *gorm.DB, migrationDir string, baseDSN string) *SchemaPerOrgBackend {
	logger, _ := zap.NewProduction()
	b := &SchemaPerOrgBackend{
		db:           db,
		baseDSN:      baseDSN,
		migrationDir: migrationDir,
		logger:       logger,
	}
	return b
}

// getOrCreateOrgDB returns a *gorm.DB with its own connection pool scoped to the org's schema.
// Each org gets a dedicated sql.DB pool so SET search_path cannot race across concurrent requests.
func (b *SchemaPerOrgBackend) getOrCreateOrgDB(ctx context.Context, orgID uuid.UUID) (*gorm.DB, error) {
	if v, ok := b.schemas.Load(orgID); ok {
		return v.(*gorm.DB), nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if v, ok := b.schemas.Load(orgID); ok {
		return v.(*gorm.DB), nil
	}

	schemaName := fmt.Sprintf("compliance_%s", orgID.String())
	quotedSchema := pq.QuoteIdentifier(schemaName)

	// Create the schema if it doesn't exist, using the shared admin connection.
	if err := b.db.Exec(fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", quotedSchema)).Error; err != nil {
		return nil, fmt.Errorf("create schema: %w", err)
	}

	// Open a dedicated connection pool for this org's schema.
	dsn := b.baseDSN
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	orgDSN := fmt.Sprintf("%s%ssearch_path=%s", dsn, sep, schemaName)

	orgDB, err := gorm.Open(postgres.Open(orgDSN), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("open org db for schema %s: %w", schemaName, err)
	}

	sqlDB, err := orgDB.DB()
	if err != nil {
		return nil, fmt.Errorf("get sql.DB for schema %s: %w", schemaName, err)
	}
	sqlDB.SetMaxOpenConns(10)
	sqlDB.SetMaxIdleConns(3)
	sqlDB.SetConnMaxLifetime(5 * time.Minute) //nolint:gomnd

	// Run migrations on the new schema.
	if b.migrationDir != "" {
		migrations, mErr := b.loadMigrations()
		if mErr != nil {
			return nil, fmt.Errorf("load migrations for schema %s: %w", schemaName, mErr)
		}
		for _, m := range migrations {
			b.logger.Info("applying migration to org schema",
				zap.String("org_id", orgID.String()),
				zap.String("file", filepath.Base(m.path)),
			)
			if err := orgDB.Exec(m.sql).Error; err != nil {
				b.logger.Error("migration failed on org schema",
					zap.String("org_id", orgID.String()),
					zap.String("file", filepath.Base(m.path)),
					zap.Error(err),
				)
				return nil, fmt.Errorf("apply migration %s: %w", filepath.Base(m.path), err)
			}
		}
	}

	b.schemas.Store(orgID, orgDB)
	b.logger.Info("provisioned schema-per-org backend",
		zap.String("org_id", orgID.String()),
		zap.String("schema", schemaName),
	)
	return orgDB, nil
}

// SetOrgContext returns a context carrying the org ID.
// The actual schema isolation is handled by the per-org connection pool created in getOrCreateOrgDB.
func (b *SchemaPerOrgBackend) SetOrgContext(ctx context.Context, orgID uuid.UUID) context.Context {
	return context.WithValue(ctx, orgKey(orgID), orgID.String())
}

// GetDB returns the shared admin DB. For schema-per-org requests, use getOrCreateOrgDB instead.
func (b *SchemaPerOrgBackend) GetDB() *gorm.DB {
	return b.db
}

func (b *SchemaPerOrgBackend) CreateOrgSchema(ctx context.Context, orgID uuid.UUID) error {
	_, err := b.getOrCreateOrgDB(ctx, orgID)
	return err
}

type migration struct {
	version int64
	path    string
	sql     string
}

func (b *SchemaPerOrgBackend) loadMigrations() ([]migration, error) {
	if b.migrationDir == "" {
		return nil, nil
	}

	entries, err := os.ReadDir(b.migrationDir)
	if err != nil {
		return nil, fmt.Errorf("read migration directory: %w", err)
	}

	var migrations []migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".up.sql") {
			continue
		}
		base := strings.TrimSuffix(e.Name(), ".up.sql")
		parts := strings.SplitN(base, "_", 2)
		if len(parts) < 2 {
			continue
		}
		v, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			continue
		}
		if v == 1 {
			continue
		}
		content, err := os.ReadFile(filepath.Join(b.migrationDir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("read migration %s: %w", e.Name(), err)
		}
		sql := strings.ReplaceAll(string(content), "compliance.", "")
		migrations = append(migrations, migration{version: v, path: filepath.Join(b.migrationDir, e.Name()), sql: sql})
	}

	sort.Slice(migrations, func(i, j int) bool { return migrations[i].version < migrations[j].version })
	return migrations, nil
}

func (b *SchemaPerOrgBackend) cleanupSchema(schemaName string) {
	if err := b.db.Exec(fmt.Sprintf("DROP SCHEMA IF EXISTS %s CASCADE", pq.QuoteIdentifier(schemaName))).Error; err != nil {
		b.logger.Error("failed to cleanup schema after error", zap.String("schema", schemaName), zap.Error(err))
	}
}

func (b *SchemaPerOrgBackend) DropOrgSchema(ctx context.Context, orgID uuid.UUID) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Close the org's dedicated pool if it exists.
	if v, ok := b.schemas.LoadAndDelete(orgID); ok {
		orgDB := v.(*gorm.DB)
		if sqlDB, err := orgDB.DB(); err == nil {
			_ = sqlDB.Close()
		}
	}

	schemaName := pq.QuoteIdentifier(fmt.Sprintf("compliance_%s", orgID.String()))
	if err := b.db.Exec(fmt.Sprintf("DROP SCHEMA IF EXISTS %s CASCADE", schemaName)).Error; err != nil {
		return fmt.Errorf("drop schema: %w", err)
	}
	return nil
}

func NewTenantBackend(db *gorm.DB, tier string, migrationDir string, baseDSN string) TenantBackend {
	switch tier {
	case "sovereign":
		return NewSchemaPerOrgBackend(db, migrationDir, baseDSN)
	default:
		return NewStandardBackend(db)
	}
}

type orgKey uuid.UUID
