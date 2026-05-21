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

func TestSlaTrackingRepository_CreateAndGetByID(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "sla_tracking")
	org := testutil.CreateTestOrg(t, db)
	repo := NewSlaTrackingRepository(db)
	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)

	deadline := time.Now().Add(72 * time.Hour)
	sla := &models.SlaTracking{
		ID:       uuid.New(),
		Cve:      "CVE-2024-0001",
		Deadline: deadline,
		Status:   "pending",
	}

	err := repo.Create(ctx, org.ID, sla)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if sla.OrgID != org.ID {
		t.Errorf("OrgID = %v, want %v", sla.OrgID, org.ID)
	}

	found, err := repo.GetByID(ctx, sla.ID)
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if found.Cve != "CVE-2024-0001" {
		t.Errorf("Cve = %q, want %q", found.Cve, "CVE-2024-0001")
	}
	if found.Status != "pending" {
		t.Errorf("Status = %q, want %q", found.Status, "pending")
	}
}

func TestSlaTrackingRepository_GetByID_NotFound(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "sla_tracking")
	org := testutil.CreateTestOrg(t, db)
	repo := NewSlaTrackingRepository(db)
	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)

	_, err := repo.GetByID(ctx, uuid.New())
	if err != ErrSlaTrackingNotFound {
		t.Errorf("expected ErrSlaTrackingNotFound, got %v", err)
	}
}

func TestSlaTrackingRepository_List(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "sla_tracking")
	org := testutil.CreateTestOrg(t, db)
	repo := NewSlaTrackingRepository(db)
	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)

	for i := 0; i < 3; i++ {
		sla := &models.SlaTracking{
			ID:       uuid.New(),
			Cve:      "CVE-2024-000" + string(rune('1'+i)),
			Deadline: time.Now().Add(time.Duration(i+1) * 24 * time.Hour),
			Status:   "pending",
		}
		if err := repo.Create(ctx, org.ID, sla); err != nil {
			t.Fatalf("Create %d failed: %v", i, err)
		}
	}

	slas, err := repo.List(ctx, 10, 0)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(slas) != 3 {
		t.Errorf("expected 3 SLA records, got %d", len(slas))
	}

	limited, err := repo.List(ctx, 2, 0)
	if err != nil {
		t.Fatalf("List with limit failed: %v", err)
	}
	if len(limited) != 2 {
		t.Errorf("expected 2 with limit, got %d", len(limited))
	}
}

func TestSlaTrackingRepository_UpdateStatus(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "sla_tracking")
	org := testutil.CreateTestOrg(t, db)
	repo := NewSlaTrackingRepository(db)
	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)

	sla := &models.SlaTracking{
		ID:       uuid.New(),
		Cve:      "CVE-2024-9999",
		Deadline: time.Now().Add(48 * time.Hour),
		Status:   "pending",
	}
	if err := repo.Create(ctx, org.ID, sla); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if err := repo.UpdateStatus(ctx, sla.ID, "resolved"); err != nil {
		t.Fatalf("UpdateStatus failed: %v", err)
	}

	found, err := repo.GetByID(ctx, sla.ID)
	if err != nil {
		t.Fatalf("GetByID after update failed: %v", err)
	}
	if found.Status != "resolved" {
		t.Errorf("Status = %q, want %q", found.Status, "resolved")
	}
}

func TestSlaTrackingRepository_ListPending(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "sla_tracking")
	org := testutil.CreateTestOrg(t, db)
	repo := NewSlaTrackingRepository(db)
	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)

	sla1 := &models.SlaTracking{
		ID:       uuid.New(),
		Cve:      "CVE-2024-1111",
		Deadline: time.Now().Add(24 * time.Hour),
		Status:   "pending",
	}
	sla2 := &models.SlaTracking{
		ID:       uuid.New(),
		Cve:      "CVE-2024-2222",
		Deadline: time.Now().Add(48 * time.Hour),
		Status:   "resolved",
	}
	if err := repo.Create(ctx, org.ID, sla1); err != nil {
		t.Fatalf("Create sla1 failed: %v", err)
	}
	if err := repo.Create(ctx, org.ID, sla2); err != nil {
		t.Fatalf("Create sla2 failed: %v", err)
	}

	pending, err := repo.ListPending(ctx)
	if err != nil {
		t.Fatalf("ListPending failed: %v", err)
	}
	if len(pending) != 1 {
		t.Errorf("expected 1 pending, got %d", len(pending))
	}
	if pending[0].Cve != "CVE-2024-1111" {
		t.Errorf("Cve = %q, want %q", pending[0].Cve, "CVE-2024-1111")
	}
}

func TestSlaTrackingRepository_ExistsByCveAndSbom(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "sla_tracking")
	org := testutil.CreateTestOrg(t, db)
	repo := NewSlaTrackingRepository(db)
	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)

	exists, err := repo.ExistsByCveAndSbom(ctx, "CVE-2024-3333", nil)
	if err != nil {
		t.Fatalf("ExistsByCveAndSbom failed: %v", err)
	}
	if exists {
		t.Error("expected false for non-existent CVE")
	}

	sla := &models.SlaTracking{
		ID:       uuid.New(),
		Cve:      "CVE-2024-3333",
		Deadline: time.Now().Add(24 * time.Hour),
		Status:   "pending",
	}
	if err := repo.Create(ctx, org.ID, sla); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	exists, err = repo.ExistsByCveAndSbom(ctx, "CVE-2024-3333", nil)
	if err != nil {
		t.Fatalf("ExistsByCveAndSbom after create failed: %v", err)
	}
	if !exists {
		t.Error("expected true after create")
	}
}

func TestSlaTrackingRepository_TenantIsolation(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "sla_tracking")
	orgA := testutil.CreateTestOrg(t, db)
	orgB := testutil.CreateTestOrg(t, db)
	repo := NewSlaTrackingRepository(db)

	ctxA := middleware.ContextWithOrgID(context.Background(), orgA.ID)
	sla := &models.SlaTracking{
		ID:       uuid.New(),
		Cve:      "CVE-2024-4444",
		Deadline: time.Now().Add(24 * time.Hour),
		Status:   "pending",
	}
	if err := repo.Create(ctxA, orgA.ID, sla); err != nil {
		t.Fatalf("Create org A failed: %v", err)
	}

	ctxB := middleware.ContextWithOrgID(context.Background(), orgB.ID)
	_, err := repo.GetByID(ctxB, sla.ID)
	if err != ErrSlaTrackingNotFound {
		t.Errorf("expected ErrSlaTrackingNotFound for cross-tenant access, got %v", err)
	}

	slasB, err := repo.List(ctxB, 10, 0)
	if err != nil {
		t.Fatalf("List org B failed: %v", err)
	}
	if len(slasB) != 0 {
		t.Errorf("expected 0 SLA records for org B, got %d", len(slasB))
	}
}
