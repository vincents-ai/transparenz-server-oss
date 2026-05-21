// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package repository

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/vincents-ai/transparenz-server-oss/pkg/middleware"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
	"github.com/vincents-ai/transparenz-server-oss/internal/testutil"
)

func TestSbomRepository_CreateAndGetByID(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "sbom_uploads")
	org := testutil.CreateTestOrg(t, db)
	repo := NewSbomRepository(db)
	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)

	upload := &models.SbomUpload{
		ID:        uuid.New(),
		Filename:  "test.spdx",
		Format:    "spdx-json",
		SizeBytes: 256,
		SHA256:    "abc123def456",
		Document:  json.RawMessage(`{"spdxVersion":"SPDX-2.3"}`),
	}

	err := repo.CreateUpload(ctx, org.ID, upload)
	if err != nil {
		t.Fatalf("CreateUpload failed: %v", err)
	}
	if upload.ID == uuid.Nil {
		t.Fatal("expected ID to be set")
	}

	found, err := repo.GetByID(ctx, upload.ID)
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if found.Filename != "test.spdx" {
		t.Errorf("Filename = %q, want %q", found.Filename, "test.spdx")
	}
	if found.Format != "spdx-json" {
		t.Errorf("Format = %q, want %q", found.Format, "spdx-json")
	}
	if found.SHA256 != "abc123def456" {
		t.Errorf("SHA256 = %q, want %q", found.SHA256, "abc123def456")
	}
}

func TestSbomRepository_GetByID_NotFound(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "sbom_uploads")
	org := testutil.CreateTestOrg(t, db)
	repo := NewSbomRepository(db)
	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)

	_, err := repo.GetByID(ctx, uuid.New())
	if err != ErrSbomUploadNotFound {
		t.Errorf("expected ErrSbomUploadNotFound, got %v", err)
	}
}

func TestSbomRepository_List(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "sbom_uploads")
	org := testutil.CreateTestOrg(t, db)
	repo := NewSbomRepository(db)
	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)

	for i := 0; i < 3; i++ {
		u := &models.SbomUpload{
			ID:        uuid.New(),
			Filename:  "sbom-" + uuid.New().String()[:8] + ".spdx",
			Format:    "spdx-json",
			SizeBytes: int64(100 + i),
			SHA256:    uuid.New().String(),
			Document:  json.RawMessage(`{"test": true}`),
		}
		if err := repo.CreateUpload(ctx, org.ID, u); err != nil {
			t.Fatalf("CreateUpload %d: %v", i, err)
		}
	}

	uploads, err := repo.List(ctx, 10, 0)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(uploads) != 3 {
		t.Errorf("expected 3 uploads, got %d", len(uploads))
	}

	uploads, err = repo.List(ctx, 2, 0)
	if err != nil {
		t.Fatalf("List with limit failed: %v", err)
	}
	if len(uploads) != 2 {
		t.Errorf("expected 2 uploads with limit, got %d", len(uploads))
	}
}

func TestSbomRepository_Delete(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "sbom_uploads")
	org := testutil.CreateTestOrg(t, db)
	repo := NewSbomRepository(db)
	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)

	upload := &models.SbomUpload{
		ID:        uuid.New(),
		Filename:  "to-delete.spdx",
		Format:    "spdx-json",
		SizeBytes: 100,
		SHA256:    "delete-me",
		Document:  json.RawMessage(`{}`),
	}

	err := repo.CreateUpload(ctx, org.ID, upload)
	if err != nil {
		t.Fatalf("CreateUpload: %v", err)
	}

	err = repo.Delete(ctx, upload.ID)
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err = repo.GetByID(ctx, upload.ID)
	if err != ErrSbomUploadNotFound {
		t.Errorf("expected ErrSbomUploadNotFound after delete, got %v", err)
	}
}

func TestSbomRepository_Delete_NotFound(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "sbom_uploads")
	org := testutil.CreateTestOrg(t, db)
	repo := NewSbomRepository(db)
	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)

	err := repo.Delete(ctx, uuid.New())
	if err != ErrSbomUploadNotFound {
		t.Errorf("expected ErrSbomUploadNotFound, got %v", err)
	}
}

func TestSbomRepository_ExistsBySHA256(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "sbom_uploads")
	org := testutil.CreateTestOrg(t, db)
	repo := NewSbomRepository(db)
	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)

	exists, err := repo.ExistsBySHA256(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("ExistsBySHA256: %v", err)
	}
	if exists {
		t.Error("expected false for non-existent SHA256")
	}

	upload := &models.SbomUpload{
		ID:        uuid.New(),
		Filename:  "dedup.spdx",
		Format:    "spdx-json",
		SizeBytes: 50,
		SHA256:    "unique-sha256",
		Document:  json.RawMessage(`{}`),
	}

	err = repo.CreateUpload(ctx, org.ID, upload)
	if err != nil {
		t.Fatalf("CreateUpload: %v", err)
	}

	exists, err = repo.ExistsBySHA256(ctx, "unique-sha256")
	if err != nil {
		t.Fatalf("ExistsBySHA256 after create: %v", err)
	}
	if !exists {
		t.Error("expected true for existing SHA256")
	}
}

func TestSbomRepository_TenantIsolation(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "sbom_uploads")
	orgA := testutil.CreateTestOrg(t, db)
	orgB := testutil.CreateTestOrg(t, db)
	repo := NewSbomRepository(db)

	ctxA := middleware.ContextWithOrgID(context.Background(), orgA.ID)
	upload := &models.SbomUpload{
		ID:        uuid.New(),
		Filename:  "org-a.spdx",
		Format:    "spdx-json",
		SizeBytes: 100,
		SHA256:    "org-a-sha",
		Document:  json.RawMessage(`{}`),
	}
	if err := repo.CreateUpload(ctxA, orgA.ID, upload); err != nil {
		t.Fatalf("CreateUpload org A: %v", err)
	}

	ctxB := middleware.ContextWithOrgID(context.Background(), orgB.ID)
	_, err := repo.GetByID(ctxB, upload.ID)
	if err != ErrSbomUploadNotFound {
		t.Errorf("expected ErrSbomUploadNotFound for cross-tenant access, got %v", err)
	}
}

func TestSbomRepository_GetDocument(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "sbom_uploads")
	org := testutil.CreateTestOrg(t, db)
	repo := NewSbomRepository(db)
	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)

	original := json.RawMessage(`{"spdxVersion":"SPDX-2.3","name":"test-pkg"}`)
	upload := &models.SbomUpload{
		ID:        uuid.New(),
		Filename:  "doc-test.spdx",
		Format:    "spdx-json",
		SizeBytes: int64(len(original)),
		SHA256:    "doc-test-sha",
		Document:  original,
	}

	err := repo.CreateUpload(ctx, org.ID, upload)
	if err != nil {
		t.Fatalf("CreateUpload: %v", err)
	}

	doc, err := repo.GetDocument(ctx, upload.ID)
	if err != nil {
		t.Fatalf("GetDocument: %v", err)
	}

	var gotMap, wantMap map[string]interface{}
	if err := json.Unmarshal(doc, &gotMap); err != nil {
		t.Fatalf("failed to unmarshal got document: %v", err)
	}
	if err := json.Unmarshal(original, &wantMap); err != nil {
		t.Fatalf("failed to unmarshal want document: %v", err)
	}
	gotJSON, _ := json.Marshal(gotMap)
	wantJSON, _ := json.Marshal(wantMap)
	if string(gotJSON) != string(wantJSON) {
		t.Errorf("document mismatch: got %s, want %s", string(gotJSON), string(wantJSON))
	}
}
