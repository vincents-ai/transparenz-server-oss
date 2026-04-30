package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	_ "github.com/lib/pq"
)

func main() {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL not set")
	}

	migrationsDir := "./migrations"
	if len(os.Args) > 1 {
		migrationsDir = os.Args[1]
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("failed to connect: %v", err)
	}
	if err := db.Ping(); err != nil {
		log.Fatalf("failed to ping: %v", err)
	}
	defer db.Close()

	_, err = db.Exec(`CREATE SCHEMA IF NOT EXISTS compliance`)
	if err != nil {
		log.Fatalf("failed to create compliance schema: %v", err) //nolint:gocritic
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS compliance.schema_migrations (
		version bigint NOT NULL PRIMARY KEY,
		dirty boolean NOT NULL DEFAULT false
	)`)
	if err != nil {
		log.Fatalf("failed to create schema_migrations: %v", err)
	}

	var currentVersion int64
	err = db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM compliance.schema_migrations WHERE dirty = false`).Scan(&currentVersion)
	if err != nil {
		log.Fatalf("failed to get current version: %v", err)
	}

	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		log.Fatalf("failed to read migrations dir: %v", err)
	}

	type migration struct {
		version int64
		path    string
	}

	var ups []migration
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
		if v > currentVersion {
			ups = append(ups, migration{version: v, path: filepath.Join(migrationsDir, e.Name())})
		}
	}

	sort.Slice(ups, func(i, j int) bool { return ups[i].version < ups[j].version })

	if len(ups) == 0 {
		fmt.Printf("migrations: already at version %d, nothing to apply\n", currentVersion)
		return
	}

	tx, err := db.Begin()
	if err != nil {
		log.Fatalf("failed to begin tx: %v", err)
	}

	for _, m := range ups {
		content, err := os.ReadFile(m.path)
		if err != nil {
			tx.Rollback() //nolint:errcheck,gosec
			log.Fatalf("failed to read %s: %v", m.path, err)
		}

		fmt.Printf("applying %06d: %s\n", m.version, filepath.Base(m.path))
		if _, err := tx.Exec(string(content)); err != nil {
			tx.Rollback() //nolint:errcheck,gosec
			log.Fatalf("failed to apply %s: %v", m.path, err)
		}

		if _, err := tx.Exec(`INSERT INTO compliance.schema_migrations (version, dirty) VALUES ($1, false) ON CONFLICT (version) DO UPDATE SET dirty = false`, m.version); err != nil {
			tx.Rollback() //nolint:errcheck,gosec
			log.Fatalf("failed to record version %d: %v", m.version, err)
		}
	}

	if err := tx.Commit(); err != nil {
		log.Fatalf("failed to commit: %v", err)
	}

	fmt.Printf("migrations: applied %d migrations, now at version %d\n", len(ups), ups[len(ups)-1].version)
}
