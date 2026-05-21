// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package repository

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vincents-ai/transparenz-server-oss/pkg/middleware"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
	"github.com/vincents-ai/transparenz-server-oss/internal/testutil"
)

func TestScanRepository_CreateAndGetByID(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "scans")
	org := testutil.CreateTestOrg(t, db)
	repo := NewScanRepository(db)
	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)

	scan := &models.Scan{
		ID:             uuid.New(),
		SbomID:         uuid.New(),
		Status:         "pending",
		ScanDate:       time.Now(),
		ScannerVersion: "0.41.0",
		ScannerSource:  "grype",
	}

	err := repo.Create(ctx, org.ID, scan)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	found, err := repo.GetByID(ctx, scan.ID)
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if found.Status != "pending" {
		t.Errorf("Status = %q, want %q", found.Status, "pending")
	}
	if found.OrgID != org.ID {
		t.Errorf("OrgID = %v, want %v", found.OrgID, org.ID)
	}
}

func TestScanRepository_GetByID_NotFound(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "scans")
	org := testutil.CreateTestOrg(t, db)
	repo := NewScanRepository(db)
	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)

	_, err := repo.GetByID(ctx, uuid.New())
	if err != ErrScanNotFound {
		t.Errorf("expected ErrScanNotFound, got %v", err)
	}
}

func TestScanRepository_List(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "scans")
	org := testutil.CreateTestOrg(t, db)
	repo := NewScanRepository(db)
	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)

	for i := 0; i < 3; i++ {
		scan := &models.Scan{
			ID:            uuid.New(),
			SbomID:        uuid.New(),
			Status:        "completed",
			ScanDate:      time.Now().Add(time.Duration(i) * time.Second),
			ScannerSource: "grype",
		}
		if err := repo.Create(ctx, org.ID, scan); err != nil {
			t.Fatalf("Create %d failed: %v", i, err)
		}
	}

	scans, err := repo.List(ctx, 10, 0)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(scans) != 3 {
		t.Errorf("expected 3 scans, got %d", len(scans))
	}

	limited, err := repo.List(ctx, 2, 0)
	if err != nil {
		t.Fatalf("List with limit failed: %v", err)
	}
	if len(limited) != 2 {
		t.Errorf("expected 2 scans with limit, got %d", len(limited))
	}
}

func TestScanRepository_Count(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "scans")
	org := testutil.CreateTestOrg(t, db)
	repo := NewScanRepository(db)
	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)

	count, err := repo.Count(ctx)
	if err != nil {
		t.Fatalf("Count failed: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 initial count, got %d", count)
	}

	scan := &models.Scan{
		ID:            uuid.New(),
		SbomID:        uuid.New(),
		Status:        "pending",
		ScanDate:      time.Now(),
		ScannerSource: "grype",
	}
	if err := repo.Create(ctx, org.ID, scan); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	count, err = repo.Count(ctx)
	if err != nil {
		t.Fatalf("Count after create failed: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 after create, got %d", count)
	}
}

func TestScanRepository_UpdateStatus(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "scans")
	org := testutil.CreateTestOrg(t, db)
	repo := NewScanRepository(db)
	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)

	scan := &models.Scan{
		ID:            uuid.New(),
		SbomID:        uuid.New(),
		Status:        "pending",
		ScanDate:      time.Now(),
		ScannerSource: "grype",
	}
	if err := repo.Create(ctx, org.ID, scan); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if err := repo.UpdateStatus(ctx, scan.ID, "completed"); err != nil {
		t.Fatalf("UpdateStatus failed: %v", err)
	}

	found, err := repo.GetByID(ctx, scan.ID)
	if err != nil {
		t.Fatalf("GetByID after update failed: %v", err)
	}
	if found.Status != "completed" {
		t.Errorf("Status = %q, want %q", found.Status, "completed")
	}
}

func TestScanRepository_TenantIsolation(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "scans")
	orgA := testutil.CreateTestOrg(t, db)
	orgB := testutil.CreateTestOrg(t, db)
	repo := NewScanRepository(db)

	ctxA := middleware.ContextWithOrgID(context.Background(), orgA.ID)
	scan := &models.Scan{
		ID:            uuid.New(),
		SbomID:        uuid.New(),
		Status:        "pending",
		ScanDate:      time.Now(),
		ScannerSource: "grype",
	}
	if err := repo.Create(ctxA, orgA.ID, scan); err != nil {
		t.Fatalf("Create org A failed: %v", err)
	}

	ctxB := middleware.ContextWithOrgID(context.Background(), orgB.ID)
	_, err := repo.GetByID(ctxB, scan.ID)
	if err != ErrScanNotFound {
		t.Errorf("expected ErrScanNotFound for cross-tenant access, got %v", err)
	}

	scansB, err := repo.List(ctxB, 10, 0)
	if err != nil {
		t.Fatalf("List org B failed: %v", err)
	}
	if len(scansB) != 0 {
		t.Errorf("expected 0 scans for org B, got %d", len(scansB))
	}
}
