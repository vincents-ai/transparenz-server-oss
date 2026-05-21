// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package repository

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vincents-ai/transparenz-server-oss/pkg/middleware"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
	"github.com/vincents-ai/transparenz-server-oss/internal/testutil"
	"gorm.io/gorm"
)

func TestVexStatementRepository_CreateAndGetByID(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "vex_statements")
	org := testutil.CreateTestOrg(t, db)
	repo := NewVexStatementRepository(db)
	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)

	stmt := &models.VexStatement{
		ID:            uuid.New(),
		CVE:           "CVE-2024-1234",
		ProductID:     "pkg:npm/example@1.0.0",
		Justification: "component_not_present",
		Confidence:    "high",
		Status:        "draft",
	}

	err := repo.Create(ctx, org.ID, stmt)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if stmt.OrgID != org.ID {
		t.Errorf("OrgID = %v, want %v", stmt.OrgID, org.ID)
	}

	found, err := repo.GetByID(ctx, stmt.ID)
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if found.CVE != "CVE-2024-1234" {
		t.Errorf("CVE = %q, want %q", found.CVE, "CVE-2024-1234")
	}
	if found.Justification != "component_not_present" {
		t.Errorf("Justification = %q, want %q", found.Justification, "component_not_present")
	}
}

func TestVexStatementRepository_GetByID_NotFound(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "vex_statements")
	org := testutil.CreateTestOrg(t, db)
	repo := NewVexStatementRepository(db)
	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)

	_, err := repo.GetByID(ctx, uuid.New())
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("expected gorm.ErrRecordNotFound, got %v", err)
	}
}

func TestVexStatementRepository_ListByOrg(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "vex_statements")
	org := testutil.CreateTestOrg(t, db)
	repo := NewVexStatementRepository(db)
	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)

	for i := 0; i < 3; i++ {
		stmt := &models.VexStatement{
			ID:            uuid.New(),
			CVE:           "CVE-2024-000" + string(rune('1'+i)),
			ProductID:     "pkg:npm/example@1.0.0",
			Justification: "component_not_present",
			Confidence:    "medium",
			Status:        "draft",
		}
		if err := repo.Create(ctx, org.ID, stmt); err != nil {
			t.Fatalf("Create %d failed: %v", i, err)
		}
	}

	stmts, err := repo.ListByOrg(ctx, org.ID, 10, 0)
	if err != nil {
		t.Fatalf("ListByOrg failed: %v", err)
	}
	if len(stmts) != 3 {
		t.Errorf("expected 3 statements, got %d", len(stmts))
	}

	limited, err := repo.ListByOrg(ctx, org.ID, 2, 0)
	if err != nil {
		t.Fatalf("ListByOrg with limit failed: %v", err)
	}
	if len(limited) != 2 {
		t.Errorf("expected 2 with limit, got %d", len(limited))
	}
}

func TestVexStatementRepository_CountByOrg(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "vex_statements")
	org := testutil.CreateTestOrg(t, db)
	repo := NewVexStatementRepository(db)
	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)

	count, err := repo.CountByOrg(ctx, org.ID)
	if err != nil {
		t.Fatalf("CountByOrg failed: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 initial count, got %d", count)
	}

	stmt := &models.VexStatement{
		ID:            uuid.New(),
		CVE:           "CVE-2024-9999",
		ProductID:     "pkg:npm/example@1.0.0",
		Justification: "component_not_present",
		Confidence:    "low",
		Status:        "draft",
	}
	if err := repo.Create(ctx, org.ID, stmt); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	count, err = repo.CountByOrg(ctx, org.ID)
	if err != nil {
		t.Fatalf("CountByOrg after create failed: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 after create, got %d", count)
	}
}

func TestVexStatementRepository_Update(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "vex_statements")
	org := testutil.CreateTestOrg(t, db)
	repo := NewVexStatementRepository(db)
	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)

	stmt := &models.VexStatement{
		ID:            uuid.New(),
		CVE:           "CVE-2024-5555",
		ProductID:     "pkg:npm/example@1.0.0",
		Justification: "component_not_present",
		Confidence:    "unknown",
		Status:        "draft",
	}
	if err := repo.Create(ctx, org.ID, stmt); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	stmt.Status = "active"
	stmt.Confidence = "high"
	if err := repo.Update(ctx, stmt); err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	found, err := repo.GetByID(ctx, stmt.ID)
	if err != nil {
		t.Fatalf("GetByID after update failed: %v", err)
	}
	if found.Status != "active" {
		t.Errorf("Status = %q, want %q", found.Status, "active")
	}
}

func TestVexStatementRepository_TenantIsolation(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "vex_statements")
	orgA := testutil.CreateTestOrg(t, db)
	orgB := testutil.CreateTestOrg(t, db)
	repo := NewVexStatementRepository(db)

	ctxA := middleware.ContextWithOrgID(context.Background(), orgA.ID)
	stmt := &models.VexStatement{
		ID:            uuid.New(),
		CVE:           "CVE-2024-7777",
		ProductID:     "pkg:npm/example@1.0.0",
		Justification: "component_not_present",
		Confidence:    "high",
		Status:        "draft",
	}
	if err := repo.Create(ctxA, orgA.ID, stmt); err != nil {
		t.Fatalf("Create org A failed: %v", err)
	}

	// org B should not see org A's records via ListByOrg
	stmtsB, err := repo.ListByOrg(context.Background(), orgB.ID, 10, 0)
	if err != nil {
		t.Fatalf("ListByOrg org B failed: %v", err)
	}
	if len(stmtsB) != 0 {
		t.Errorf("expected 0 statements for org B, got %d", len(stmtsB))
	}

	// GetByID with org B context should not find org A record (TenantScope)
	ctxB := middleware.ContextWithOrgID(context.Background(), orgB.ID)
	now := time.Now().Add(24 * time.Hour)
	stmt.ValidUntil = &now
	_, err = repo.GetByID(ctxB, stmt.ID)
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("expected gorm.ErrRecordNotFound for cross-tenant access, got %v", err)
	}
}
