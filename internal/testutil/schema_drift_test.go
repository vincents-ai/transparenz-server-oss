package testutil

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file exists because the SQLite schema the unit tests run against is a
// HAND-WRITTEN COPY of what the migrations produce. That copy has drifted from
// reality repeatedly, and every time it did, the unit tests passed against a
// schema the product does not ship.
//
// The drift is not hypothetical. It has produced at least four real defects:
//   - four Organization columns in the model that no migration created, so a
//     database built from the real migrations could not insert a row
//   - a CHECK constraint admitting only NULL or five named values, against a Go
//     string that wrote '' — invisible to every test, because the SQLite schema
//     carries no CHECK constraints at all
//   - a migration that collapsed an event-type allow-list from seventeen values
//     to six
//   - a NOT NULL column omitted by a test step
//
// The three copies (migrations, the commercial test schema, the OSS test
// schema) now differ from each other in different directions. Rather than
// trying to keep them in sync by hand — which is what produced the drift —
// this test makes divergence a build failure. It is the inverse of a guard that
// cannot fail: here the check is expected to fail whenever reality moves, and
// someone must go and look.
//
// It compares COLUMNS and the PRESENCE OF CHECK CONSTRAINTS. It does not attempt
// to verify constraint bodies, which would be brittle; a table that has
// constraints in the migrations and none in the test schema is reported, so the
// gap stays visible.

func TestSQLiteTestSchemaMatchesMigrations(t *testing.T) {
	migrationCols, _, err := loadSchemaFromMigrations(t)
	require.NoError(t, err, "could not read migrations")

	testCols, _, err := loadSchemaFromTestDDL(t)
	require.NoError(t, err, "could not read the test schema")

	// --- columns present in migrations but absent from the test schema -----
	// This is the direction that hides bugs: a column the product writes but
	// the tests do not have simply does not exist during a unit test.
	//
	// Scoped to the tables the test schema actually models. The schema is
	// deliberately partial — the Article 14 and CRA tables are exercised by
	// the BDD suite against a real PostgreSQL, not by unit tests — so
	// demanding every migrated table here would be measuring the wrong thing
	// and would fail on a deliberate design choice rather than on drift.
	var missing []string
	for table, cols := range migrationCols {
		modelled, ok := testCols[table]
		if !ok {
			continue
		}
		for col := range cols {
			if _, ok := modelled[col]; !ok {
				missing = append(missing, table+"."+col)
			}
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("the SQLite test schema is missing %d column(s) that the migrations create:\n  %s\n\n"+
			"Add them to the allDDL map in internal/testutil/testdb.go, or the unit tests "+
			"will keep passing against a schema the product does not ship.",
			len(missing), strings.Join(missing, "\n  "))
	}

	// --- tables in the test schema that the migrations do not create -------
	// This IS drift in the dangerous direction: the tests model a table the
	// product does not have, so they validate against something that cannot
	// exist in a real deployment.
	var unknown []string
	for table := range testCols {
		if _, ok := migrationCols[table]; !ok {
			unknown = append(unknown, table)
		}
	}
	sort.Strings(unknown)
	if len(unknown) > 0 {
		t.Errorf("the SQLite test schema defines %d table(s) that no migration creates:\n  %s",
			len(unknown), strings.Join(unknown, "\n  "))
	}
}

func TestSQLiteTestSchemaCarriesCheckConstraints(t *testing.T) {
	migrationChecked, err := loadCheckedTablesFromMigrations(t)
	require.NoError(t, err)

	_, testChecked, err := loadSchemaFromTestDDL(t)
	require.NoError(t, err)

	var missing []string
	for table := range migrationChecked {
		if !testChecked[table] {
			missing = append(missing, table)
		}
	}
	sort.Strings(missing)

	if len(missing) > 0 {
		// Not fatal. SQLite supports CHECK constraints and the reason they are
		// absent is historical, but every table in this list has a constraint
		// that has already been violated in production-shaped code without a
		// test noticing.
		t.Logf("the SQLite test schema carries no CHECK constraint for %d table(s) that the "+
			"migrations constrain:\n  %s\n\n"+
			"These are the tables where a constraint violation passes unit tests and only "+
			"surfaces against a real database.",
			len(missing), strings.Join(missing, "\n  "))
	}
}

// --- parsing -------------------------------------------------------------

var (
	migrationCreateTable = regexp.MustCompile(`(?is)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:\w+\.)?(\w+)\s*\((.*?)\n\)\s*;`)
	// A single ALTER TABLE may add several columns in one statement, comma
	// separated, so the whole statement is captured and the ADD COLUMN clauses
	// are extracted from its body rather than matching the first one only.
	migrationAlterTable  = regexp.MustCompile(`(?is)ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:\w+\.)?(\w+)\s+([^;]*);`)
	migrationAddColumnIn = regexp.MustCompile(`(?i)ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)`)
	migrationTableCheck  = regexp.MustCompile(`(?is)ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:\w+\.)?(\w+)\s+ADD\s+CONSTRAINT\b[^;]*?\bCHECK\s*\(`)

	// Column definition keywords that can appear as the first token of a line
	// inside a CREATE TABLE body and are therefore not columns.
	nonColumnKeywords = map[string]bool{
		"PRIMARY": true, "UNIQUE": true, "CHECK": true, "CONSTRAINT": true,
		"FOREIGN": true, "EXCLUDE": true, "LIKE": true,
	}
)

// splitTopLevel splits a CREATE TABLE body on commas that are not nested
// inside parentheses, quotes or a comment. Naive splitting breaks the moment a
// CHECK constraint contains a comma, which most of them do.
func splitTopLevel(body string) []string {
	var parts []string
	var cur strings.Builder
	depth := 0
	inSingle, inDouble, inDollar := false, false, false
	inLineComment := false

	runes := []rune(body)
	for i := 0; i < len(runes); i++ {
		c := runes[i]

		if inLineComment {
			if c == '\n' {
				inLineComment = false
				cur.WriteRune(c)
			}
			continue
		}
		if !inSingle && !inDouble && !inDollar && c == '-' && i+1 < len(runes) && runes[i+1] == '-' {
			inLineComment = true
			i++
			continue
		}
		if inDollar {
			if c == '$' && i+1 < len(runes) && runes[i+1] == '$' {
				inDollar = false
				i++
			}
			cur.WriteRune(c)
			continue
		}
		if inSingle {
			if c == '\'' {
				inSingle = false
			}
			cur.WriteRune(c)
			continue
		}
		if inDouble {
			if c == '"' {
				inDouble = false
			}
			cur.WriteRune(c)
			continue
		}

		switch c {
		case '\'':
			inSingle = true
		case '"':
			inDouble = true
		case '$':
			inDollar = true
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, cur.String())
				cur.Reset()
				continue
			}
		}
		cur.WriteRune(c)
	}
	if s := strings.TrimSpace(cur.String()); s != "" {
		parts = append(parts, s)
	}
	return parts
}

// leadingIdentifier returns the leading bare identifier of a column
// definition, ignoring a trailing "(" so that a table constraint such as
// UNIQUE (org_id, cve) yields "UNIQUE" rather than "unique(org_id,".
var leadingIdentifier = regexp.MustCompile(`^"?(?:\w+\.)?"?([A-Za-z_][A-Za-z0-9_]*)"?`)

func columnNameFromDef(def string) (string, bool) {
	cleaned := stripLineComments(def)
	cleaned = strings.TrimSpace(cleaned)
	if cleaned == "" {
		return "", false
	}
	id := leadingIdentifier.FindStringSubmatch(cleaned)
	if id == nil {
		return "", false
	}
	first := id[1]
	if first == "" || nonColumnKeywords[strings.ToUpper(first)] {
		return "", false
	}
	// A quoted, possibly schema-qualified identifier.
	if idx := strings.Index(first, "."); idx >= 0 {
		first = first[idx+1:]
	}
	return strings.ToLower(strings.Trim(first, `"`)), true
}

func stripLineComments(s string) string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

func migrationsDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("..", "..", "migrations")
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("cannot find migrations directory at %s: %v", dir, err)
	}
	return dir
}

func loadSchemaFromMigrations(t *testing.T) (map[string]map[string]bool, map[string]bool, error) {
	cols := map[string]map[string]bool{}
	checked := map[string]bool{}

	entries, err := os.ReadDir(migrationsDir(t))
	if err != nil {
		return nil, nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".up.sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(migrationsDir(t), name))
		if err != nil {
			return nil, nil, err
		}
		sql := string(data)

		for _, m := range migrationCreateTable.FindAllStringSubmatch(sql, -1) {
			table := strings.ToLower(m[1])
			if cols[table] == nil {
				cols[table] = map[string]bool{}
			}
			for _, def := range splitTopLevel(m[2]) {
				if c, ok := columnNameFromDef(def); ok {
					cols[table][c] = true
				}
			}
			if strings.Contains(strings.ToUpper(m[2]), "CHECK") {
				checked[table] = true
			}
		}
		for _, m := range migrationAlterTable.FindAllStringSubmatch(sql, -1) {
			table := strings.ToLower(m[1])
			if cols[table] == nil {
				cols[table] = map[string]bool{}
			}
			for _, c := range migrationAddColumnIn.FindAllStringSubmatch(m[2], -1) {
				cols[table][strings.ToLower(c[1])] = true
			}
		}
		for _, m := range migrationTableCheck.FindAllStringSubmatch(sql, -1) {
			checked[strings.ToLower(m[1])] = true
		}
	}
	return cols, checked, nil
}

func loadCheckedTablesFromMigrations(t *testing.T) (map[string]bool, error) {
	_, checked, err := loadSchemaFromMigrations(t)
	return checked, err
}

// The test DDL is stored in Go raw string literals, so the delimiter is a
// backtick. \x60 is used rather than a literal backtick because a literal one
// would terminate the raw string holding this pattern.
var testDDLTable = regexp.MustCompile(`(?is)"(\w+)":\s*\x60\s*CREATE\s+TABLE[^\x60]*?\((.*?)\n\s*\)\x60`)

func loadSchemaFromTestDDL(t *testing.T) (map[string]map[string]bool, map[string]bool, error) {
	data, err := os.ReadFile("testdb.go")
	if err != nil {
		return nil, nil, err
	}
	src := string(data)

	cols := map[string]map[string]bool{}
	checked := map[string]bool{}

	for _, m := range testDDLTable.FindAllStringSubmatch(src, -1) {
		table := strings.ToLower(m[1])
		if cols[table] == nil {
			cols[table] = map[string]bool{}
		}
		for _, def := range splitTopLevel(m[2]) {
			if c, ok := columnNameFromDef(def); ok {
				cols[table][c] = true
			}
		}
		if strings.Contains(strings.ToUpper(m[2]), "CHECK") {
			checked[table] = true
		}
	}
	return cols, checked, nil
}

// TestSchemaParserHandlesRealMigrations is a self-check on the parsing above.
// A drift detector that silently parses nothing would report zero drift and be
// worse than useless, so the parser is asserted against known facts.
func TestSchemaParserHandlesRealMigrations(t *testing.T) {
	cols, _, err := loadSchemaFromMigrations(t)
	require.NoError(t, err)

	require.NotEmpty(t, cols, "the migration parser found no tables at all")
	require.Contains(t, cols, "organizations", "organizations should be parsed from migration 000002")
	require.Contains(t, cols, "sla_tracking")
	require.Contains(t, cols, "compliance_events")

	// Inline CHECK on a column definition, with commas inside the IN list —
	// this is what a naive comma split gets wrong.
	assert.True(t, cols["organizations"]["enisa_submission_mode"],
		"a column carrying an inline CHECK must still be recognised as a column")
	assert.True(t, cols["organizations"]["csirt_endpoint"],
		"a column added by a later ALTER TABLE must be picked up")
	assert.False(t, cols["organizations"]["constraint"],
		"a bare CONSTRAINT keyword is not a column")

	// Columns added by ALTER TABLE, which is where csirt_endpoint lives.
	assert.True(t, cols["organizations"]["nis2_member_state"],
		"columns added by ALTER TABLE ADD COLUMN must be included")
}

func TestSplitTopLevelIgnoresCommasInsideConstraints(t *testing.T) {
	body := "a text, b text CHECK (b IN ('x', 'y', 'z')), c integer"
	parts := splitTopLevel(body)
	assert.Len(t, parts, 3, "commas inside a CHECK must not split the definition")
}
