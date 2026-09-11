package repository

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// testSchemaDB connects to the test PostgreSQL instance or skips the test.
func testSchemaDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := "postgres://user:pass@localhost:5432/transparenz_test?search_path=compliance"
	if d := os.Getenv("TEST_DATABASE_URL"); d != "" {
		dsn = d
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Skipf("test database not available: %v", err)
	}
	return db
}

// TestSchemaPerOrg_ConcurrentCreation tests the double-checked locking path:
// concurrent goroutines creating a schema for the same org should all succeed
// without deadlock or duplicate schema creation errors.
func TestSchemaPerOrg_ConcurrentCreation(t *testing.T) {
	db := testSchemaDB(t)
	orgID := uuid.New()
	schemaName := fmt.Sprintf("compliance_%s", orgID.String())

	// Cleanup
	t.Cleanup(func() {
		db.Exec(fmt.Sprintf("DROP SCHEMA IF EXISTS %s CASCADE", quoteIdent(schemaName)))
	})

	backend := NewSchemaPerOrgBackend(db, "", testDSNForSchema(t))

	var wg sync.WaitGroup
	errors := make([]error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			errors[idx] = backend.CreateOrgSchema(context.Background(), orgID)
		}(i)
	}
	wg.Wait()

	for i, err := range errors {
		assert.NoError(t, err, "goroutine %d should succeed", i)
	}

	// Verify schema exists
	var count int64
	db.Raw("SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name = ?", schemaName).Scan(&count)
	assert.Equal(t, int64(1), count, "schema should exist exactly once")
}

// TestSchemaPerOrg_SchemaNameEscaping verifies that org IDs with unusual
// characters produce valid schema names (UUIDs should be safe, but verify).
func TestSchemaPerOrg_SchemaNameEscaping(t *testing.T) {
	db := testSchemaDB(t)
	orgID := uuid.New()
	schemaName := fmt.Sprintf("compliance_%s", orgID.String())

	t.Cleanup(func() {
		db.Exec(fmt.Sprintf("DROP SCHEMA IF EXISTS %s CASCADE", quoteIdent(schemaName)))
	})

	backend := NewSchemaPerOrgBackend(db, "", testDSNForSchema(t))
	err := backend.CreateOrgSchema(context.Background(), orgID)
	require.NoError(t, err)

	// Schema should exist
	var count int64
	db.Raw("SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name = ?", schemaName).Scan(&count)
	assert.Equal(t, int64(1), count)
}

// TestSchemaPerOrg_DropClosesPoolAndDropsSchema verifies that DropOrgSchema
// closes the connection pool and drops the schema.
func TestSchemaPerOrg_DropClosesPoolAndDropsSchema(t *testing.T) {
	db := testSchemaDB(t)
	orgID := uuid.New()
	schemaName := fmt.Sprintf("compliance_%s", orgID.String())

	t.Cleanup(func() {
		db.Exec(fmt.Sprintf("DROP SCHEMA IF EXISTS %s CASCADE", quoteIdent(schemaName)))
	})

	backend := NewSchemaPerOrgBackend(db, "", testDSNForSchema(t))

	// Create the schema
	err := backend.CreateOrgSchema(context.Background(), orgID)
	require.NoError(t, err)

	// Verify schema exists
	var count int64
	db.Raw("SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name = ?", schemaName).Scan(&count)
	assert.Equal(t, int64(1), count)

	// Drop the schema
	err = backend.DropOrgSchema(context.Background(), orgID)
	require.NoError(t, err)

	// Verify schema is gone
	db.Raw("SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name = ?", schemaName).Scan(&count)
	assert.Equal(t, int64(0), count, "schema should be dropped")

	// Pool entry should be removed
	_, exists := backend.schemas.Load(orgID)
	assert.False(t, exists, "connection pool should be removed from cache")
}

// TestSchemaPerOrg_CrossSchemaIsolation verifies that queries against one org's
// schema cannot see another org's data.
func TestSchemaPerOrg_CrossSchemaIsolation(t *testing.T) {
	db := testSchemaDB(t)
	orgA := uuid.New()
	orgB := uuid.New()
	schemaA := fmt.Sprintf("compliance_%s", orgA.String())
	schemaB := fmt.Sprintf("compliance_%s", orgB.String())

	t.Cleanup(func() {
		db.Exec(fmt.Sprintf("DROP SCHEMA IF EXISTS %s CASCADE", quoteIdent(schemaA)))
		db.Exec(fmt.Sprintf("DROP SCHEMA IF EXISTS %s CASCADE", quoteIdent(schemaB)))
	})

	backend := NewSchemaPerOrgBackend(db, "", testDSNForSchema(t))
	require.NoError(t, backend.CreateOrgSchema(context.Background(), orgA))
	require.NoError(t, backend.CreateOrgSchema(context.Background(), orgB))

	// Insert data into org A's schema
	orgDBA, err := backend.getOrCreateOrgDB(context.Background(), orgA)
	require.NoError(t, err)
	require.NoError(t, orgDBA.Exec("CREATE TABLE IF NOT EXISTS test_data (id text PRIMARY KEY, value text)").Error)
	require.NoError(t, orgDBA.Exec("INSERT INTO test_data (id, value) VALUES (?, ?)", "1", "secret-a").Error)

	// Insert data into org B's schema
	orgDBB, err := backend.getOrCreateOrgDB(context.Background(), orgB)
	require.NoError(t, err)
	require.NoError(t, orgDBB.Exec("CREATE TABLE IF NOT EXISTS test_data (id text PRIMARY KEY, value text)").Error)
	require.NoError(t, orgDBB.Exec("INSERT INTO test_data (id, value) VALUES (?, ?)", "1", "secret-b").Error)

	// Verify org A sees its own data
	var valA string
	require.NoError(t, orgDBA.Raw("SELECT value FROM test_data WHERE id = ?", "1").Scan(&valA).Error)
	assert.Equal(t, "secret-a", valA, "org A should see its own data")

	// Verify org B sees its own data
	var valB string
	require.NoError(t, orgDBB.Raw("SELECT value FROM test_data WHERE id = ?", "1").Scan(&valB).Error)
	assert.Equal(t, "secret-b", valB, "org B should see its own data")

	// Verify org B cannot see org A's data (different schemas)
	var countFromB int64
	require.NoError(t, orgDBB.Raw("SELECT COUNT(*) FROM test_data WHERE value = ?", "secret-a").Scan(&countFromB).Error)
	assert.Equal(t, int64(0), countFromB, "org B should not see org A's data")
}

// testDSNForSchema extracts a base DSN from the test database URL.
func testDSNForSchema(t *testing.T) string {
	t.Helper()
	dsn := "postgres://user:pass@localhost:5432/transparenz_test"
	if d := os.Getenv("TEST_DATABASE_URL"); d != "" {
		// Strip search_path from DSN
		dsn = strings.Split(d, "?")[0]
	}
	return dsn
}

func quoteIdent(name string) string {
	return fmt.Sprintf(`"%s"`, strings.ReplaceAll(name, `"`, `""`))
}
