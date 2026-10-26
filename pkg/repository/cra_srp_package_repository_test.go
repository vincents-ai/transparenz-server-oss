// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.

package repository

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/vincents-ai/transparenz-server-oss/pkg/regulatory"
	"github.com/vincents-ai/transparenz-server-oss/pkg/regulatory/srp"
)

// srpPackageTestDB builds an in-memory database with the one table these tests
// touch.
//
// It does not use setupTestDB because that helper requires PostgreSQL and skips
// when none is running, and a skipped test is not evidence that the revision
// logic works. The DDL below is a local transcription of migration 000050 with
// the PostgreSQL-only pieces (JSONB, the append-only trigger) replaced by their
// nearest SQLite equivalent; the append-only guarantee is therefore asserted by
// the migration, not here.
func srpPackageTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.Exec(`ATTACH DATABASE ':memory:' AS compliance`).Error)
	require.NoError(t, db.Exec(`CREATE TABLE compliance.cra_srp_packages (
		id text PRIMARY KEY,
		org_id text NOT NULL,
		report_id text NOT NULL,
		stage text NOT NULL,
		revision integer NOT NULL,
		schema_id text NOT NULL,
		event_class text NOT NULL,
		coordinator_id text NOT NULL,
		fields text NOT NULL,
		digest text NOT NULL,
		generated_at datetime NOT NULL,
		created_at datetime,
		created_by text NOT NULL,
		UNIQUE (report_id, stage, revision),
		UNIQUE (report_id, stage, digest)
	)`).Error)
	return db
}

// buildV16ForTest returns the schema the builder is expected to be used with.
func buildV16ForTest() (*regulatory.ReportingSchema, error) {
	return regulatory.BuildSRPGlossaryV16Schema(
		"ENISA_OPERATIONAL_GUIDANCE|ENISA SRP Glossary|1.6",
		time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC),
	)
}

// sealedPackage builds a real package through the builder, so the digest under
// test is one the production code produced rather than a literal.
func sealedPackage(t *testing.T, reportID, orgID uuid.UUID, summary string) srp.Package {
	t.Helper()
	schema, err := buildV16ForTest()
	require.NoError(t, err)

	fields := map[string]string{
		regulatory.FieldV16NotificationType: "Vulnerability",
		regulatory.FieldV16Title:            "Active exploitation affecting Example Gateway 4.2",
		regulatory.FieldV16Summary:          summary,
		regulatory.FieldV16ManufacturerName: "Example Manufacturing GmbH",
		regulatory.FieldV16MemberStates:     "Germany",
		regulatory.FieldV16ProductName:      "Example Gateway",
		regulatory.FieldV16ProductVersion:   "4.0 to 4.2.1",
		regulatory.FieldV16AEVAwareness:     "2026-09-20 08:45 UTC",
	}
	pkg, err := srp.Build(schema, srp.BuildInput{
		ReportID:      reportID,
		OrgID:         orgID,
		EventClass:    regulatory.EventClassAEV,
		Stage:         regulatory.StageEarlyWarning,
		CoordinatorID: "DE-CSIRT",
		Fields:        fields,
		Now:           time.Date(2026, 9, 20, 9, 30, 0, 0, time.UTC),
	})
	require.NoError(t, err)
	return pkg
}

func TestSRPPackageStoreIsIdempotentPerDocument(t *testing.T) {
	db := srpPackageTestDB(t)
	repo := NewSRPPackageRepository(db)
	reportID, orgID := uuid.New(), uuid.New()

	first := sealedPackage(t, reportID, orgID, "An actively exploited authentication bypass.")
	stored, err := repo.Store(t.Context(), first, "user:analyst-a")
	require.NoError(t, err)
	assert.Equal(t, 1, stored.Revision)
	assert.Equal(t, first.Digest, stored.Digest)
	assert.Equal(t, "user:analyst-a", stored.CreatedBy)

	// The same document again. Not a new revision: a revision that differs only
	// in its creation time would read as a change to the document.
	again, err := repo.Store(t.Context(), first, "user:analyst-b")
	require.NoError(t, err)
	assert.Equal(t, stored.ID, again.ID, "an identical package must resolve to the stored row")

	history, err := repo.History(t.Context(), orgID, reportID, string(first.Stage))
	require.NoError(t, err)
	assert.Len(t, history, 1)
}

func TestSRPPackageStoreAppendsRevisionsAndKeepsTheOldOne(t *testing.T) {
	db := srpPackageTestDB(t)
	repo := NewSRPPackageRepository(db)
	reportID, orgID := uuid.New(), uuid.New()

	first := sealedPackage(t, reportID, orgID, "Initial summary.")
	second := sealedPackage(t, reportID, orgID, "Revised summary after further analysis.")
	require.NotEqual(t, first.Digest, second.Digest)

	storedFirst, err := repo.Store(t.Context(), first, "user:analyst-a")
	require.NoError(t, err)
	storedSecond, err := repo.Store(t.Context(), second, "user:analyst-a")
	require.NoError(t, err)

	assert.Equal(t, 1, storedFirst.Revision)
	assert.Equal(t, 2, storedSecond.Revision)

	history, err := repo.History(t.Context(), orgID, reportID, string(first.Stage))
	require.NoError(t, err)
	require.Len(t, history, 2)
	assert.Equal(t, 1, history[0].Revision, "history is oldest first")
	assert.Equal(t, first.Digest, history[0].Digest)

	latest, err := repo.Latest(t.Context(), orgID, reportID, string(first.Stage))
	require.NoError(t, err)
	assert.Equal(t, 2, latest.Revision)
}

// A digest lookup is scoped by organisation, report AND stage. Anything less
// would let a package filed for one tenant, or for one stage, evidence another.
func TestSRPPackageLookupIsScopedByOrgReportAndStage(t *testing.T) {
	db := srpPackageTestDB(t)
	repo := NewSRPPackageRepository(db)
	orgA, orgB := uuid.New(), uuid.New()
	reportA := uuid.New()
	otherReport := uuid.New()

	pkg := sealedPackage(t, reportA, orgA, "A summary.")
	_, err := repo.Store(t.Context(), pkg, "user:a")
	require.NoError(t, err)

	// The digest identifies the document, so the same digest under a different
	// tenant must not be found.
	_, err = repo.ByDigest(t.Context(), orgB, reportA, string(pkg.Stage), pkg.Digest)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNoBuiltPackage))

	_, err = repo.ByDigest(t.Context(), orgA, otherReport, string(pkg.Stage), pkg.Digest)
	require.Error(t, err)

	_, err = repo.ByDigest(t.Context(), orgA, reportA, "final_report", pkg.Digest)
	require.Error(t, err, "a package must not be found under a stage it was not built for")

	found, err := repo.ByDigest(t.Context(), orgA, reportA, string(pkg.Stage), pkg.Digest)
	require.NoError(t, err)
	assert.Equal(t, pkg.Digest, found.Digest)
}

// An unsealed package, or an anonymous one, is refused before any row exists: a
// package with no digest evidences nothing, and one with no actor is a
// determination nobody made.
func TestSRPPackageStoreRefusesUnusableEvidence(t *testing.T) {
	db := srpPackageTestDB(t)
	repo := NewSRPPackageRepository(db)
	reportID, orgID := uuid.New(), uuid.New()
	pkg := sealedPackage(t, reportID, orgID, "A summary.")

	unsealed := pkg
	unsealed.Digest = ""
	_, err := repo.Store(t.Context(), unsealed, "user:a")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no digest")

	_, err = repo.Store(t.Context(), pkg, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "attributable")

	orphan := pkg
	orphan.ReportID = uuid.Nil
	_, err = repo.Store(t.Context(), orphan, "user:a")
	require.Error(t, err)
}

// The reason the field set is retained: verification is a comparison, not a
// claim. A row whose fields no longer reproduce its digest must fail.
func TestStoredPackageVerifiesFromItsRetainedFields(t *testing.T) {
	db := srpPackageTestDB(t)
	repo := NewSRPPackageRepository(db)
	reportID, orgID := uuid.New(), uuid.New()

	pkg := sealedPackage(t, reportID, orgID, "A summary.")
	stored, err := repo.Store(t.Context(), pkg, "user:a")
	require.NoError(t, err)

	rebuilt := ToPackage(stored)
	assert.True(t, rebuilt.VerifyDigest(), "a stored package must reproduce its own digest")
	assert.Equal(t, pkg.Digest, rebuilt.Digest)

	// Editing the retained field set breaks the claim, which is the whole point
	// of keeping the fields next to the digest.
	stored.Fields[regulatory.FieldV16Summary] = "A summary nobody sealed."
	assert.False(t, ToPackage(stored).VerifyDigest())
}
