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

	// Whether this call is creating the organisation's schema or upgrading one
	// that already exists. The difference decides what happens on failure: a
	// half-built NEW schema is dropped and retried, while a failed UPGRADE must
	// leave the existing data alone.
	var alreadyExists bool
	if err := b.db.Raw(`SELECT EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = ?)`,
		schemaName).Scan(&alreadyExists).Error; err != nil {
		return nil, fmt.Errorf("look up schema %s: %w", schemaName, err)
	}

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
		// The schema exists but no usable pool came from it. Drop it rather
		// than leaving a half-built org schema behind, which is what
		// cleanupSchema was written for and why it existed unused.
		b.cleanupSchema(schemaName)
		return nil, fmt.Errorf("open org db for schema %s: %w", schemaName, err)
	}

	sqlDB, err := orgDB.DB()
	if err != nil {
		b.cleanupSchema(schemaName)
		return nil, fmt.Errorf("get sql.DB for schema %s: %w", schemaName, err)
	}
	sqlDB.SetMaxOpenConns(10)
	sqlDB.SetMaxIdleConns(3)
	sqlDB.SetConnMaxLifetime(5 * time.Minute) //nolint:gomnd

	// Apply pending migrations, tracking versions inside the organisation's own
	// schema.
	//
	// Without the version table every provisioning call replayed the entire
	// migration sequence, which only ever worked because a new schema starts
	// empty. An organisation whose schema already exists — the normal case after
	// the first release that adds a migration — was either re-run from the start
	// (failing on the first CREATE TABLE that now exists) or, in practice, never
	// upgraded at all, so the schema a tenant was provisioned with was the schema
	// it kept forever.
	if b.migrationDir != "" {
		migrations, mErr := b.loadMigrations(schemaName)
		if mErr != nil {
			_ = sqlDB.Close()
			if !alreadyExists {
				b.cleanupSchema(schemaName)
			}
			return nil, fmt.Errorf("load migrations for schema %s: %w", schemaName, mErr)
		}

		if err := ensureMigrationState(orgDB); err != nil {
			_ = sqlDB.Close()
			if !alreadyExists {
				b.cleanupSchema(schemaName)
			}
			return nil, fmt.Errorf("prepare migration state in schema %s: %w", schemaName, err)
		}

		applied, aErr := appliedVersions(orgDB)
		if aErr != nil {
			_ = sqlDB.Close()
			if !alreadyExists {
				b.cleanupSchema(schemaName)
			}
			return nil, fmt.Errorf("read applied migrations in schema %s: %w", schemaName, aErr)
		}

		for _, m := range migrations {
			if applied[m.version] {
				continue
			}
			b.logger.Info("applying migration to org schema",
				zap.String("org_id", orgID.String()),
				zap.String("file", filepath.Base(m.path)),
				zap.Bool("upgrading_existing", alreadyExists),
			)
			if err := applyMigration(orgDB, m); err != nil {
				b.logger.Error("migration failed on org schema",
					zap.String("org_id", orgID.String()),
					zap.String("file", filepath.Base(m.path)),
					zap.Bool("upgrading_existing", alreadyExists),
					zap.Error(err),
				)
				_ = sqlDB.Close()
				if alreadyExists {
					// Do NOT drop an organisation's existing schema because an
					// upgrade failed: the applied versions are recorded, so a retry
					// resumes from the migration that failed, and destroying the
					// tenant's data to "clean up" would be the worst possible
					// recovery.
					return nil, fmt.Errorf("apply migration %s: %w", filepath.Base(m.path), err)
				}
				b.cleanupSchema(schemaName)
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

func (b *SchemaPerOrgBackend) loadMigrations(schemaName string) ([]migration, error) {
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
		// Point the statements at this organisation's schema explicitly. The
		// previous version deleted the "compliance." prefix and relied on the
		// pool's search_path; that works, but it also rewrites the string
		// wherever it appears — including inside a literal — and it leaves the
		// statements unqualified, so a future pool that loses search_path
		// silently writes to whatever schema comes first. Substituting the real
		// schema name keeps the statements qualified and makes the target
		// explicit. It is still a textual substitution, which is the honest
		// description: a fully SQL-aware transformer would be better and is not
		// what this is.
		sql := strings.ReplaceAll(string(content), "compliance.", pq.QuoteIdentifier(schemaName)+".")
		migrations = append(migrations, migration{version: v, path: filepath.Join(b.migrationDir, e.Name()), sql: sql})
	}

	sort.Slice(migrations, func(i, j int) bool { return migrations[i].version < migrations[j].version })
	return migrations, nil
}

// ensureMigrationState creates the per-schema version table if it is missing.
func ensureMigrationState(db *gorm.DB) error {
	return db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version BIGINT PRIMARY KEY,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`).Error
}

// appliedVersions returns the migration versions already applied in this schema.
func appliedVersions(db *gorm.DB) (map[int64]bool, error) {
	var rows []struct{ Version int64 }
	if err := db.Raw(`SELECT version FROM schema_migrations`).Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[int64]bool, len(rows))
	for _, r := range rows {
		out[r.Version] = true
	}
	return out, nil
}

// applyMigration runs one migration and records its version.
//
// The version is written only after the statements succeed, so an interrupted
// migration is retried rather than skipped. Both steps share a transaction where
// PostgreSQL allows it; DDL is transactional there, which is the case that matters.
func applyMigration(db *gorm.DB, m migration) error {
	return db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(m.sql).Error; err != nil {
			return err
		}
		return tx.Exec(`INSERT INTO schema_migrations (version) VALUES (?) ON CONFLICT (version) DO NOTHING`,
			m.version).Error
	})
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
