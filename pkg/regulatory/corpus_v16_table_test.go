// SPDX-FileCopyrightText: 2026 Vincent Palmer
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Transparenz, an open-source CRA compliance server.
// It is licensed under the GNU Affero General Public License v3.0; see LICENSE.

package regulatory

import (
	"bufio"
	_ "embed"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The published requiredness matrix, extracted from the glossary page itself.
//
// This is the difference between asserting that the schema matches our
// transcription and asserting that it matches the authority's table. The
// transcription could be wrong in the same direction as the code — a mistaken
// reading carried into both — and no test that compares code to transcription
// would ever notice.
//
//go:embed ENISA_SRP_GLOSSARY_v1.6.table.tsv
var srpGlossaryV16Table []byte

// publishedRow is one line of the extracted table.
type publishedRow struct {
	Position  string
	Applies   string
	EW        string
	H72       string
	FR        string
	FieldName string
}

func parsePublishedTable(t *testing.T) []publishedRow {
	t.Helper()
	var rows []publishedRow
	scanner := bufio.NewScanner(strings.NewReader(string(srpGlossaryV16Table)))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	headerSeen := false
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !headerSeen {
			require.Equal(t, "position\tapplies\tEW\t72h\tFR\tfield", line,
				"the extracted table's header is not the one this parser expects")
			headerSeen = true
			continue
		}
		parts := strings.Split(line, "\t")
		require.Len(t, parts, 6, "malformed row in the extracted table: %q", line)
		rows = append(rows, publishedRow{
			Position: parts[0], Applies: parts[1],
			EW: parts[2], H72: parts[3], FR: parts[4],
			FieldName: parts[5],
		})
	}
	require.NoError(t, scanner.Err())
	require.True(t, headerSeen, "the extracted table has no header row")
	return rows
}

// requirementFor maps the published vocabulary onto regulatory.Requirement.
//
// The glossary uses Required, Mandatory, Optional (with stage-specific
// qualifiers), N/A, and two editorial forms — "by default copied from the
// previous step" and "required if such information is available" — which both
// mean the value carries forward when it exists. An unrecognised value is a
// failure rather than a default: a silent default is how a new glossary revision
// gets absorbed without anyone noticing it changed.
func requirementFor(t *testing.T, position, stage, published string) Requirement {
	t.Helper()
	switch {
	case published == "Required", published == "Mandatory":
		return RequirementRequired
	case published == "N/A":
		return RequirementNotApplicable
	case strings.HasPrefix(published, "Optional"):
		return RequirementOptional
	case strings.HasPrefix(published, "By default copied"):
		return RequirementInheritedOrUpdate
	case strings.HasPrefix(published, "Required if"):
		return RequirementInheritedOrUpdate
	default:
		t.Fatalf("%s at %s: unrecognised published requirement %q; the glossary vocabulary "+
			"has changed and this mapping needs reviewing", position, stage, published)
		return ""
	}
}

// classesFor maps the published applicability onto event classes.
func classesFor(t *testing.T, position, applies string) []EventClass {
	t.Helper()
	switch applies {
	case "Both":
		return []EventClass{EventClassAEV, EventClassSI}
	case "AEV":
		return []EventClass{EventClassAEV}
	case "SI":
		return []EventClass{EventClassSI}
	default:
		t.Fatalf("%s: unrecognised applicability %q", position, applies)
		return nil
	}
}

// TestV16MatrixMatchesThePublishedTable is the conformance guard for the
// transcription itself.
func TestV16MatrixMatchesThePublishedTable(t *testing.T) {
	rows := parsePublishedTable(t)
	require.NotEmpty(t, rows)

	schema, err := BuildSRPGlossaryV16Schema("k", time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err)

	// 43 published positions: 1-18 including 7a, v19-v30 including v26a, i31-i39,
	// and the two case-management positions.
	require.Len(t, rows, 43, "the extracted table should hold every published position")
	require.Len(t, schema.Fields(), len(rows),
		"the schema must define exactly the published positions")

	seen := map[string]bool{}
	for _, row := range rows {
		t.Run(row.Position, func(t *testing.T) {
			require.False(t, seen[row.Position], "position %s appears twice in the extracted table", row.Position)
			seen[row.Position] = true

			f, ok := schema.Field(row.Position)
			require.True(t, ok, "the schema does not define published position %s (%s)", row.Position, row.FieldName)

			// Name: the first two words of our name must appear in the published
			// one. Published names carry parenthetical qualifiers and trailing
			// punctuation, so an exact match would be brittle in one direction and
			// silent in the other.
			assert.True(t, nameAgrees(f.Name, row.FieldName),
				"position %s is named %q here but %q in the published table", row.Position, f.Name, row.FieldName)

			classes := classesFor(t, row.Position, row.Applies)
			for _, class := range classes {
				assert.True(t, f.AppliesTo(class),
					"position %s applies to %s in the published table", row.Position, row.Applies)
			}
			if row.Applies != "Both" {
				for _, class := range []EventClass{EventClassAEV, EventClassSI} {
					if class != classes[0] {
						assert.False(t, f.AppliesTo(class),
							"position %s does not apply to %s in the published table", row.Position, class)
					}
				}
			}

			for _, tc := range []struct {
				stage     Stage
				published string
			}{
				{StageEarlyWarning, row.EW},
				{StageNotification72h, row.H72},
				{StageFinalReport, row.FR},
			} {
				want := requirementFor(t, row.Position, string(tc.stage), tc.published)
				for _, class := range classes {
					assert.Equal(t, want, f.RequirementAt(tc.stage, class),
						"position %s at %s/%s is %q in the published table",
						row.Position, class, tc.stage, tc.published)
				}
			}
		})
	}
}

// nameAgrees reports whether our field name and the published one describe the
// same thing, tolerating the published table's parenthetical qualifiers.
func nameAgrees(ours, published string) bool {
	our := strings.ToLower(strings.TrimSpace(ours))
	pub := strings.ToLower(published)

	words := strings.Fields(our)
	if len(words) == 0 {
		return false
	}
	probe := words[0]
	if len(probe) < 4 && len(words) > 1 {
		probe = words[0] + " " + words[1]
	}
	if len(probe) > 24 {
		probe = probe[:24]
	}
	return strings.Contains(pub, probe)
}
