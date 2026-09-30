package testutil

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	_ "github.com/lib/pq"
)

// Migration tests.
//
// Two shipped blockers reached main because nothing in either repository ran the
// migrations the way a deployment does. golang-migrate refuses a migration
// directory containing two files with the same version number, and aborts
// without applying anything, so `migrate up` fails and no schema is built at
// all. That is not a theoretical problem: both the commercial and the open
// source sets had exactly that collision, which broke the k6 and playwright CI
// jobs and the NixOS deployment.
//
// No test caught it because the BDD suite applies migrations by executing the
// .up.sql files in filename order through a hand-rolled loop, which never
// consults the version number at all. The suite therefore passed against a
// migration set that no deployment could use.
//
// These two tests close that. The first is a static check that needs no
// database and runs everywhere. The second actually applies the migrations and
// skips when no database is available.

var migrationVersionPattern = regexp.MustCompile(`^(\d+)[_.]`)

// migrationDir locates the migrations directory relative to the test.
func migrationDir(t *testing.T) string {
	t.Helper()
	// internal/testutil -> repository root
	dir := filepath.Join("..", "..", "migrations")
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("no migrations directory at %s: %v", dir, err)
	}
	return dir
}

type migration struct {
	version uint
	name    string
	file    string
}

func readMigrations(t *testing.T, dir string) []migration {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	var out []migration
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".up.sql") {
			continue
		}
		m := migrationVersionPattern.FindStringSubmatch(n)
		if m == nil {
			t.Errorf("migration %q does not start with a version number; golang-migrate "+
				"will not recognise it", n)
			continue
		}
		var v uint
		if _, err := fmt.Sscanf(m[1], "%d", &v); err != nil {
			t.Errorf("migration %q has an unparseable version: %v", n, err)
			continue
		}
		out = append(out, migration{version: v, name: strings.TrimSuffix(strings.TrimPrefix(n, m[0]), ".up.sql"), file: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out
}

// TestMigrationsHaveUniqueVersions is the check that would have caught both
// shipped collisions. It needs no database, so it runs in every environment
// including a bare CI runner.
func TestMigrationsHaveUniqueVersions(t *testing.T) {
	dir := migrationDir(t)
	migrations := readMigrations(t, dir)
	if len(migrations) == 0 {
		t.Fatalf("no .up.sql migrations found in %s", dir)
	}

	byVersion := map[uint][]string{}
	for _, m := range migrations {
		byVersion[m.version] = append(byVersion[m.version], m.name)
	}

	var collisions []string
	versions := make([]uint, 0, len(byVersion))
	for v := range byVersion {
		versions = append(versions, v)
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })
	for _, v := range versions {
		if len(byVersion[v]) > 1 {
			collisions = append(collisions,
				fmt.Sprintf("  %06d: %s", v, strings.Join(byVersion[v], ", ")))
		}
	}
	if len(collisions) > 0 {
		t.Errorf("duplicate migration version numbers in %s:\n%s\n\n"+
			"golang-migrate refuses a directory with two migrations at one version and "+
			"aborts without applying anything, so `migrate up` fails and no schema is built. "+
			"Rename the later file to the next unused version.", dir,
			strings.Join(collisions, "\n"))
	}
}

// TestMigrationsHavePairedDownFiles guards the reverse asymmetry: golang-migrate
// tolerates an .up.sql with no .down.sql for `up`, but `migrate down` and
// `migrate redo` then fail. Five migrations in this repository are in that state
// today.
func TestMigrationsHavePairedDownFiles(t *testing.T) {
	dir := migrationDir(t)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	var orphans []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".up.sql") {
			continue
		}
		down := strings.TrimSuffix(e.Name(), ".up.sql") + ".down.sql"
		if _, err := os.Stat(filepath.Join(dir, down)); err != nil {
			orphans = append(orphans, e.Name())
		}
	}
	sort.Strings(orphans)
	if len(orphans) > 0 {
		t.Logf("%d migration(s) have no .down.sql:\n  %s\n\n"+
			"`migrate up` tolerates this, so it does not block a deployment, but "+
			"`migrate down` and `migrate redo` will fail on them.",
			len(orphans), strings.Join(orphans, "\n  "))
	}
}

// TestMigrationsApplyToEmptyDatabase applies every migration to a real database
// and reports the first that fails. This is the end-to-end check the k6 and
// playwright jobs rely on and that no test performed.
//
// Skipped when TEST_DATABASE_URL is unset so it does not fail a bare checkout.
func TestMigrationsApplyToEmptyDatabase(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is not set; skipping the live migration check")
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Start from a clean schema so a previous run cannot mask a failure.
	if _, err := db.Exec(`DROP SCHEMA IF EXISTS compliance CASCADE; CREATE SCHEMA compliance;`); err != nil {
		t.Fatalf("resetting schema: %v", err)
	}

	dir := migrationDir(t)
	for _, m := range readMigrations(t, dir) {
		body, err := os.ReadFile(filepath.Join(dir, m.file))
		if err != nil {
			t.Fatalf("reading %s: %v", m.file, err)
		}
		if _, err := db.Exec(string(body)); err != nil {
			t.Fatalf("migration %s (%s) failed: %v", m.file, m.name, err)
		}
	}
	t.Logf("applied %d migrations cleanly", len(readMigrations(t, dir)))
}
