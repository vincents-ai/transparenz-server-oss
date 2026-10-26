// SPDX-FileCopyrightText: 2026 Vincent Palmer
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Transparenz, an open-source CRA compliance server.
// It is licensed under the GNU Affero General Public License v3.0; see LICENSE.

package repository

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vincents-ai/transparenz-server-oss/internal/testutil"
	"github.com/vincents-ai/transparenz-server-oss/pkg/middleware"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
)

// A compliance dashboard that shows "no outstanding obligations" while an SBOM has
// never been scanned against the current feed is not reporting compliance, it is
// reporting that nothing has been looked for. This is the test for the signal that
// distinguishes the two.
func TestScanFreshnessDistinguishesScannedFromUnlookedAt(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "sbom_uploads", "scans", "vulnerability_feeds")
	repo := NewSbomRepository(db)

	org := testutil.CreateTestOrg(t, db)
	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)

	feedSynced := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	require.NoError(t, db.Create(&models.VulnerabilityFeed{
		ID: uuid.New(), Cve: "CVE-2026-1111", LastSyncedAt: feedSynced,
	}).Error)

	mkSbom := func(name string) models.SbomUpload {
		up := models.SbomUpload{
			ID: uuid.New(), OrgID: org.ID, Filename: name, Format: "cyclonedx-json",
			SizeBytes: 2, SHA256: "aa", Document: []byte("{}"),
		}
		require.NoError(t, db.Create(&up).Error)
		return up
	}
	mkScan := func(sbomID uuid.UUID, at time.Time) {
		require.NoError(t, db.Create(&models.Scan{
			ID: uuid.New(), OrgID: org.ID, SbomID: sbomID, Status: "completed",
			ScannerSource: "grype", ScanDate: at,
		}).Error)
	}

	never := mkSbom("never-scanned.cdx.json")
	before := mkSbom("scanned-before-sync.cdx.json")
	mkScan(before.ID, feedSynced.Add(-48*time.Hour))
	after := mkSbom("scanned-after-sync.cdx.json")
	mkScan(after.ID, feedSynced.Add(2*time.Hour))

	got, err := repo.Freshness(ctx)
	require.NoError(t, err)

	require.NotNil(t, got.FeedLastSyncedAt)
	assert.WithinDuration(t, feedSynced, *got.FeedLastSyncedAt, time.Second)
	assert.Equal(t, 3, got.Total)
	assert.Equal(t, 2, got.Stale, "the never-scanned SBOM and the one scanned before the sync")
	assert.NotEmpty(t, got.Note, "the caveat travels with the numbers")

	byID := map[uuid.UUID]SbomFreshness{}
	for _, s := range got.Sboms {
		byID[s.SbomID] = s
	}

	assert.True(t, byID[never.ID].Stale, "never scanned means nothing has been looked for")
	assert.Nil(t, byID[never.ID].LastScannedAt)

	assert.True(t, byID[before.ID].Stale,
		"scanned before the latest feed sync: the feed has changed since")
	assert.False(t, byID[before.ID].ScannedAfterFeedSync)

	assert.False(t, byID[after.ID].Stale, "scanned after the latest feed sync")
	assert.True(t, byID[after.ID].ScannedAfterFeedSync)
	assert.Equal(t, "completed", byID[after.ID].LastScanStatus)
}

// With no feed at all there is nothing to be stale against, and an SBOM that has
// been scanned is fresh by definition. Asserted so the empty case cannot silently
// report everything as stale and send an operator chasing nothing.
func TestScanFreshnessWithNoFeedData(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "sbom_uploads", "scans", "vulnerability_feeds")
	repo := NewSbomRepository(db)

	org := testutil.CreateTestOrg(t, db)
	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)

	up := models.SbomUpload{
		ID: uuid.New(), OrgID: org.ID, Filename: "a.cdx.json", Format: "cyclonedx-json",
		SizeBytes: 2, SHA256: "bb", Document: []byte("{}"),
	}
	require.NoError(t, db.Create(&up).Error)
	require.NoError(t, db.Create(&models.Scan{
		ID: uuid.New(), OrgID: org.ID, SbomID: up.ID, Status: "completed",
		ScannerSource: "grype", ScanDate: time.Now().UTC().Add(-time.Hour),
	}).Error)

	got, err := repo.Freshness(ctx)
	require.NoError(t, err)
	assert.Nil(t, got.FeedLastSyncedAt)
	assert.Equal(t, 1, got.Total)
	assert.Equal(t, 0, got.Stale, "nothing to be stale against")
}
