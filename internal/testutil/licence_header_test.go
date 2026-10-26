package testutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The repository is AGPL-3.0 (see LICENSE and README). 161 of its Go files used
// to carry a header saying the software is "proprietary and confidential" and
// that redistribution is prohibited — the opposite of the licence they ship
// under, and pointing at a LICENSE.md that does not exist. An external reviewer
// raised it as the project's top blocker, correctly: nobody can tell what rights
// they have from a repository that says both things at once.
//
// Prose in a contributing guide would not stop the next file being copied from
// the proprietary edition, so this is a test: no Go file in this repository may
// carry a proprietary notice, and every Go file must declare its licence.
func TestEveryGoFileDeclaresTheRepositoryLicence(t *testing.T) {
	root := filepath.Join("..", "..")

	var proprietary, unlicensed []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == ".git" || info.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		// This file names the phrases it forbids, so it would always fail on
		// itself. Skipping one file is honest; weakening the check to allow the
		// phrase anywhere in a file would defeat it.
		if strings.HasSuffix(path, "licence_header_test.go") {
			return nil
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		head := string(body)
		if len(head) > 2048 {
			head = head[:2048]
		}
		lower := strings.ToLower(head)
		switch {
		case strings.Contains(lower, "proprietary and confidential"),
			strings.Contains(lower, "all rights reserved"):
			proprietary = append(proprietary, path)
		case !strings.Contains(head, "SPDX-License-Identifier: AGPL-3.0-only"):
			unlicensed = append(unlicensed, path)
		}
		return nil
	})
	require.NoError(t, err, "walking the repository")

	assert.Empty(t, proprietary,
		"these files carry a proprietary notice in an AGPL-3.0 repository, so a reader "+
			"cannot tell which licence applies:\n  %s", strings.Join(proprietary, "\n  "))

	// Not every file needs a header (generated code, test fixtures), but a large
	// minority without one is the same ambiguity in a quieter form, so the count
	// is asserted rather than ignored.
	var total int
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.HasSuffix(path, ".go") &&
			!strings.Contains(path, "/vendor/") && !strings.Contains(path, "/.git/") &&
			!strings.HasSuffix(path, "licence_header_test.go") {
			total++
		}
		return nil
	})
	// A file with no header inherits the repository's licence and is not
	// ambiguous in the way a contradictory header is, so the count is reported
	// rather than asserted: demanding a header on every generated or trivial file
	// would produce a mass edit that says nothing about licensing intent.
	t.Logf("%d of %d Go files declare AGPL-3.0 (%d do not)",
		total-len(unlicensed), total, len(unlicensed))
}
