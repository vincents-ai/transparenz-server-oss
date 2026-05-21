// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package repository

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/vincents-ai/transparenz-server-oss/pkg/middleware"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
	"github.com/vincents-ai/transparenz-server-oss/internal/testutil"
)

func TestEnisaSubmissionRepository_CreateAndGetByID(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "enisa_submissions")
	org := testutil.CreateTestOrg(t, db)
	repo := NewEnisaSubmissionRepository(db)
	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)

	submission := &models.EnisaSubmission{
		ID:           uuid.New(),
		SubmissionID: "SUB-" + uuid.New().String()[:8],
		CsafDocument: models.JSONMap{"document_type": "csaf_vex"},
		Status:       "pending",
	}

	err := repo.Create(ctx, org.ID, submission)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if submission.OrgID != org.ID {
		t.Errorf("OrgID = %v, want %v", submission.OrgID, org.ID)
	}

	found, err := repo.GetByID(ctx, submission.ID)
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

func TestEnisaSubmissionRepository_GetByID_NotFound(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "enisa_submissions")
	org := testutil.CreateTestOrg(t, db)
	repo := NewEnisaSubmissionRepository(db)
	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)

	_, err := repo.GetByID(ctx, uuid.New())
	if err != ErrEnisaSubmissionNotFound {
		t.Errorf("expected ErrEnisaSubmissionNotFound, got %v", err)
	}
}

func TestEnisaSubmissionRepository_List(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "enisa_submissions")
	org := testutil.CreateTestOrg(t, db)
	repo := NewEnisaSubmissionRepository(db)
	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)

	for i := 0; i < 3; i++ {
		sub := &models.EnisaSubmission{
			ID:           uuid.New(),
			SubmissionID: "SUB-" + uuid.New().String()[:8],
			CsafDocument: models.JSONMap{"index": i},
			Status:       "pending",
		}
		if err := repo.Create(ctx, org.ID, sub); err != nil {
			t.Fatalf("Create %d failed: %v", i, err)
		}
	}

	submissions, err := repo.List(ctx, 10, 0)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(submissions) != 3 {
		t.Errorf("expected 3 submissions, got %d", len(submissions))
	}

	limited, err := repo.List(ctx, 2, 0)
	if err != nil {
		t.Fatalf("List with limit failed: %v", err)
	}
	if len(limited) != 2 {
		t.Errorf("expected 2 with limit, got %d", len(limited))
	}
}

func TestEnisaSubmissionRepository_UpdateStatus(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "enisa_submissions")
	org := testutil.CreateTestOrg(t, db)
	repo := NewEnisaSubmissionRepository(db)
	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)

	submission := &models.EnisaSubmission{
		ID:           uuid.New(),
		SubmissionID: "SUB-STATUS-" + uuid.New().String()[:8],
		CsafDocument: models.JSONMap{"test": true},
		Status:       "pending",
	}
	if err := repo.Create(ctx, org.ID, submission); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if err := repo.UpdateStatus(ctx, submission.ID, "submitted"); err != nil {
		t.Fatalf("UpdateStatus failed: %v", err)
	}

	found, err := repo.GetByID(ctx, submission.ID)
	if err != nil {
		t.Fatalf("GetByID after update failed: %v", err)
	}
	if found.Status != "submitted" {
		t.Errorf("Status = %q, want %q", found.Status, "submitted")
	}
}

func TestEnisaSubmissionRepository_IncrementRetry(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "enisa_submissions")
	org := testutil.CreateTestOrg(t, db)
	repo := NewEnisaSubmissionRepository(db)
	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)

	submission := &models.EnisaSubmission{
		ID:           uuid.New(),
		SubmissionID: "SUB-RETRY-" + uuid.New().String()[:8],
		CsafDocument: models.JSONMap{"retry": true},
		Status:       "failed",
		RetryCount:   0,
	}
	if err := repo.Create(ctx, org.ID, submission); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if err := repo.IncrementRetry(ctx, submission.ID); err != nil {
		t.Fatalf("IncrementRetry failed: %v", err)
	}

	found, err := repo.GetByID(ctx, submission.ID)
	if err != nil {
		t.Fatalf("GetByID after increment failed: %v", err)
	}
	if found.RetryCount != 1 {
		t.Errorf("RetryCount = %d, want 1", found.RetryCount)
	}
}

func TestEnisaSubmissionRepository_TenantIsolation(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "enisa_submissions")
	orgA := testutil.CreateTestOrg(t, db)
	orgB := testutil.CreateTestOrg(t, db)
	repo := NewEnisaSubmissionRepository(db)

	ctxA := middleware.ContextWithOrgID(context.Background(), orgA.ID)
	sub := &models.EnisaSubmission{
		ID:           uuid.New(),
		SubmissionID: "SUB-ISO-" + uuid.New().String()[:8],
		CsafDocument: models.JSONMap{"org": "A"},
		Status:       "pending",
	}
	if err := repo.Create(ctxA, orgA.ID, sub); err != nil {
		t.Fatalf("Create org A failed: %v", err)
	}

	ctxB := middleware.ContextWithOrgID(context.Background(), orgB.ID)
	_, err := repo.GetByID(ctxB, sub.ID)
	if err != ErrEnisaSubmissionNotFound {
		t.Errorf("expected ErrEnisaSubmissionNotFound for cross-tenant access, got %v", err)
	}

	subsB, err := repo.List(ctxB, 10, 0)
	if err != nil {
		t.Fatalf("List org B failed: %v", err)
	}
	if len(subsB) != 0 {
		t.Errorf("expected 0 submissions for org B, got %d", len(subsB))
	}
}
