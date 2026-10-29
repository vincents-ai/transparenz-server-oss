// SPDX-FileCopyrightText: 2026 Vincent Palmer
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Transparenz, an open-source CRA compliance server.
// It is licensed under the GNU Affero General Public License v3.0; see LICENSE.

//go:build integration

package repository

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/vincents-ai/transparenz-server-oss/internal/testutil"
	"github.com/vincents-ai/transparenz-server-oss/pkg/middleware"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
)

// The shared-database mode has no row-level security: the application is the only
// boundary, and every query must scope itself with repository.TenantScope or an
// explicit org predicate. That makes "does this repository leak?" a question with
// one answer per method, and the honest way to answer it for all of them is a
// matrix rather than a claim.
//
// Each case seeds a row owned by tenant B, then reads and lists it as tenant A.
// The test is table-driven so a new repository can be added with a few lines, and
// written so a missing scope fails here rather than in production.
type isolationCase struct {
	name string
	// seed creates one row owned by orgID and returns its id.
	seed func(t *testing.T, db *gorm.DB, orgID uuid.UUID) uuid.UUID
	// get reads the row as the caller's tenant.
	get func(ctx context.Context, id uuid.UUID) (any, error)
	// list returns the ids visible to the caller's tenant.
	list func(ctx context.Context) ([]uuid.UUID, error)
}

func TestTenantIsolationAcrossRepositories(t *testing.T) {
	db := setupTenantTestDB(t)

	orgA := testutil.CreateTestOrg(t, db).ID
	orgB := testutil.CreateTestOrg(t, db).ID
	ctxA := middleware.ContextWithOrgID(context.Background(), orgA)

	sbomRepo := NewSbomRepository(db)
	scanRepo := NewScanRepository(db)
	slaRepo := NewSlaTrackingRepository(db)
	vexRepo := NewVexStatementRepository(db)
	enisaRepo := NewEnisaSubmissionRepository(db)
	discRepo := NewVulnerabilityDisclosureRepository(db)

	cases := []isolationCase{
		{
			name: "sbom uploads",
			seed: func(t *testing.T, db *gorm.DB, orgID uuid.UUID) uuid.UUID {
				up := models.SbomUpload{
					ID: uuid.New(), OrgID: orgID, Filename: "b.cdx.json",
					Format: "cyclonedx-json", SizeBytes: 2, SHA256: "iso-b-" + orgID.String()[:8],
					Document: []byte("{}"),
				}
				require.NoError(t, db.Create(&up).Error)
				return up.ID
			},
			get: func(ctx context.Context, id uuid.UUID) (any, error) { return sbomRepo.GetByID(ctx, id) },
			list: func(ctx context.Context) ([]uuid.UUID, error) {
				rows, err := sbomRepo.List(ctx, 100, 0)
				ids := make([]uuid.UUID, 0, len(rows))
				for _, r := range rows {
					ids = append(ids, r.ID)
				}
				return ids, err
			},
		},
		{
			name: "scans",
			seed: func(t *testing.T, db *gorm.DB, orgID uuid.UUID) uuid.UUID {
				// A scan has a foreign key to an SBOM, so the owner needs one. It is
				// created with the row rather than reused, and it belongs to the same
				// tenant, so it cannot mask a missing scope on the scan query.
				sbomID := uuid.New()
				require.NoError(t, db.Create(&models.SbomUpload{
					ID: sbomID, OrgID: orgID, Filename: "scan-owner.cdx.json",
					Format: "cyclonedx-json", SizeBytes: 2,
					SHA256: "iso-scan-" + orgID.String()[:8], Document: []byte("{}"),
				}).Error)

				sc := models.Scan{
					ID: uuid.New(), OrgID: orgID, SbomID: sbomID, Status: "completed",
					ScanDate: time.Now().UTC(), ScannerSource: "grype",
				}
				require.NoError(t, db.Create(&sc).Error)
				return sc.ID
			},
			get: func(ctx context.Context, id uuid.UUID) (any, error) { return scanRepo.GetByID(ctx, id) },
			list: func(ctx context.Context) ([]uuid.UUID, error) {
				rows, err := scanRepo.List(ctx, 100, 0)
				ids := make([]uuid.UUID, 0, len(rows))
				for _, r := range rows {
					ids = append(ids, r.ID)
				}
				return ids, err
			},
		},
		{
			name: "sla tracking",
			seed: func(t *testing.T, db *gorm.DB, orgID uuid.UUID) uuid.UUID {
				sla := models.SlaTracking{
					ID: uuid.New(), OrgID: orgID, Cve: "CVE-2026-9001",
					Deadline: time.Now().UTC().Add(24 * time.Hour), Status: "pending",
				}
				require.NoError(t, db.Create(&sla).Error)
				return sla.ID
			},
			get: func(ctx context.Context, id uuid.UUID) (any, error) { return slaRepo.GetByID(ctx, id) },
			list: func(ctx context.Context) ([]uuid.UUID, error) {
				rows, err := slaRepo.List(ctx, 100, 0)
				ids := make([]uuid.UUID, 0, len(rows))
				for _, r := range rows {
					ids = append(ids, r.ID)
				}
				return ids, err
			},
		},
		{
			name: "vex statements",
			seed: func(t *testing.T, db *gorm.DB, orgID uuid.UUID) uuid.UUID {
				v := models.VexStatement{
					ID: uuid.New(), OrgID: orgID, CVE: "CVE-2026-9002",
					Justification: "vulnerable_code_not_in_execute_path", Confidence: "high",
				}
				require.NoError(t, db.Create(&v).Error)
				return v.ID
			},
			get: func(ctx context.Context, id uuid.UUID) (any, error) { return vexRepo.GetByID(ctx, id) },
			list: func(ctx context.Context) ([]uuid.UUID, error) {
				rows, err := vexRepo.ListByOrg(ctx, orgA, 100, 0)
				ids := make([]uuid.UUID, 0, len(rows))
				for _, r := range rows {
					ids = append(ids, r.ID)
				}
				return ids, err
			},
		},
		{
			name: "enisa submissions",
			seed: func(t *testing.T, db *gorm.DB, orgID uuid.UUID) uuid.UUID {
				// submission_id is uniquely indexed and defaults to '', so it has to
				// be distinct per row.
				sub := models.EnisaSubmission{
					ID: uuid.New(), OrgID: orgID, Status: "pending",
					SubmissionID: "iso-" + uuid.New().String()[:8],
					CsafDocument: models.JSONMap{"document": map[string]any{}},
				}
				require.NoError(t, db.Create(&sub).Error)
				return sub.ID
			},
			get: func(ctx context.Context, id uuid.UUID) (any, error) { return enisaRepo.GetByID(ctx, id) },
			list: func(ctx context.Context) ([]uuid.UUID, error) {
				rows, err := enisaRepo.List(ctx, 100, 0)
				ids := make([]uuid.UUID, 0, len(rows))
				for _, r := range rows {
					ids = append(ids, r.ID)
				}
				return ids, err
			},
		},
		{
			name: "vulnerability disclosures",
			seed: func(t *testing.T, db *gorm.DB, orgID uuid.UUID) uuid.UUID {
				d := models.VulnerabilityDisclosure{
					ID: uuid.New(), OrgID: orgID, Cve: "CVE-2026-9003",
					Title: "Reported issue", Status: "received",
				}
				require.NoError(t, db.Create(&d).Error)
				return d.ID
			},
			get: func(ctx context.Context, id uuid.UUID) (any, error) { return discRepo.GetByID(ctx, id) },
			list: func(ctx context.Context) ([]uuid.UUID, error) {
				rows, err := discRepo.List(ctx, 100, 0)
				ids := make([]uuid.UUID, 0, len(rows))
				for _, r := range rows {
					ids = append(ids, r.ID)
				}
				return ids, err
			},
		},
	}

	require.NotEmpty(t, cases)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			idOfB := tc.seed(t, db, orgB)

			// Reading another tenant's row by id must fail.
			got, err := tc.get(ctxA, idOfB)
			if err == nil {
				assert.Nil(t, got,
					"tenant A read tenant B's %s by id; the query is not scoped", tc.name)
			}

			// And it must not appear in a list.
			ids, err := tc.list(ctxA)
			require.NoError(t, err)
			assert.NotContains(t, ids, idOfB,
				"tenant B's %s appeared in tenant A's list", tc.name)

			// The owning tenant can still read it, so the assertions above are not
			// passing because nothing works.
			ctxB := middleware.ContextWithOrgID(context.Background(), orgB)
			if _, err := tc.get(ctxB, idOfB); err != nil {
				t.Fatalf("tenant B cannot read its own %s: %v — the isolation assertions "+
					"above would pass vacuously", tc.name, err)
			}
		})
	}
}

// A context with no organisation must see nothing, not everything. TenantScope
// fails closed with WHERE 1=0, and that is the property that keeps a forgotten
// middleware from turning into a full disclosure.
func TestTenantScopeFailsClosedWithoutAnOrganisation(t *testing.T) {
	db := setupTenantTestDB(t)

	org := testutil.CreateTestOrg(t, db).ID
	up := models.SbomUpload{
		ID: uuid.New(), OrgID: org, Filename: "x.cdx.json", Format: "cyclonedx-json",
		SizeBytes: 2, SHA256: "iso-closed", Document: []byte("{}"),
	}
	require.NoError(t, db.Create(&up).Error)

	anon := context.Background()
	rows, err := NewSbomRepository(db).List(anon, 100, 0)
	require.NoError(t, err)
	assert.Empty(t, rows, "with no organisation in context, a scoped list must return nothing")

	if got, err := NewSbomRepository(db).GetByID(anon, up.ID); err == nil {
		assert.Nil(t, got, "with no organisation in context, a scoped read must return nothing")
	}
}
