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
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
	"github.com/vincents-ai/transparenz-server-oss/internal/testutil"
)

func TestSbomWebhookRepository_CreateAndGetByID(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "sbom_webhooks")
	org := testutil.CreateTestOrg(t, db)
	repo := NewSbomWebhookRepository(db)
	ctx := context.Background()

	webhook := &models.SbomWebhook{
		ID:         uuid.New(),
		OrgID:      org.ID,
		Name:       "Test SBOM Webhook",
		SecretHash: "hashed-secret-" + uuid.New().String(),
		Active:     true,
		Actions: models.SbomWebhookActions{
			TriggerScan: true,
		},
	}

	err := repo.CreateWebhook(ctx, webhook)
	if err != nil {
		t.Fatalf("CreateWebhook failed: %v", err)
	}

	found, err := repo.GetWebhookByID(ctx, webhook.ID)
	if err != nil {
		t.Fatalf("GetWebhookByID failed: %v", err)
	}
	if found.Name != "Test SBOM Webhook" {
		t.Errorf("Name = %q, want %q", found.Name, "Test SBOM Webhook")
	}
	if found.OrgID != org.ID {
		t.Errorf("OrgID = %v, want %v", found.OrgID, org.ID)
	}
}

func TestSbomWebhookRepository_GetWebhookByID_NotFound(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "sbom_webhooks")
	repo := NewSbomWebhookRepository(db)
	ctx := context.Background()

	_, err := repo.GetWebhookByID(ctx, uuid.New())
	if err != ErrSbomWebhookNotFound {
		t.Errorf("expected ErrSbomWebhookNotFound, got %v", err)
	}
}

func TestSbomWebhookRepository_ListWebhooksByOrg(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "sbom_webhooks")
	org := testutil.CreateTestOrg(t, db)
	repo := NewSbomWebhookRepository(db)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		wh := &models.SbomWebhook{
			ID:         uuid.New(),
			OrgID:      org.ID,
			Name:       "Webhook " + string(rune('A'+i)),
			SecretHash: "hash-" + uuid.New().String(),
			Active:     true,
		}
		if err := repo.CreateWebhook(ctx, wh); err != nil {
			t.Fatalf("CreateWebhook %d failed: %v", i, err)
		}
	}

	webhooks, err := repo.ListWebhooksByOrg(ctx, org.ID, 10, 0)
	if err != nil {
		t.Fatalf("ListWebhooksByOrg failed: %v", err)
	}
	if len(webhooks) != 3 {
		t.Errorf("expected 3 webhooks, got %d", len(webhooks))
	}

	limited, err := repo.ListWebhooksByOrg(ctx, org.ID, 2, 0)
	if err != nil {
		t.Fatalf("ListWebhooksByOrg with limit failed: %v", err)
	}
	if len(limited) != 2 {
		t.Errorf("expected 2 webhooks with limit, got %d", len(limited))
	}
}

func TestSbomWebhookRepository_DeleteWebhook(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "sbom_webhooks")
	org := testutil.CreateTestOrg(t, db)
	repo := NewSbomWebhookRepository(db)
	ctx := context.Background()

	webhook := &models.SbomWebhook{
		ID:         uuid.New(),
		OrgID:      org.ID,
		Name:       "To Delete",
		SecretHash: "delete-hash-" + uuid.New().String(),
		Active:     true,
	}
	if err := repo.CreateWebhook(ctx, webhook); err != nil {
		t.Fatalf("CreateWebhook failed: %v", err)
	}

	if err := repo.DeleteWebhook(ctx, webhook.ID, org.ID); err != nil {
		t.Fatalf("DeleteWebhook failed: %v", err)
	}

	_, err := repo.GetWebhookByID(ctx, webhook.ID)
	if err != ErrSbomWebhookNotFound {
		t.Errorf("expected ErrSbomWebhookNotFound after delete, got %v", err)
	}
}

func TestSbomWebhookRepository_DeleteWebhook_NotFound(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "sbom_webhooks")
	org := testutil.CreateTestOrg(t, db)
	repo := NewSbomWebhookRepository(db)
	ctx := context.Background()

	err := repo.DeleteWebhook(ctx, uuid.New(), org.ID)
	if err != ErrSbomWebhookNotFound {
		t.Errorf("expected ErrSbomWebhookNotFound, got %v", err)
	}
}

func TestSbomWebhookRepository_CountWebhooksByOrg(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "sbom_webhooks")
	org := testutil.CreateTestOrg(t, db)
	repo := NewSbomWebhookRepository(db)
	ctx := context.Background()

	count, err := repo.CountWebhooksByOrg(ctx, org.ID)
	if err != nil {
		t.Fatalf("CountWebhooksByOrg failed: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 initial count, got %d", count)
	}

	webhook := &models.SbomWebhook{
		ID:         uuid.New(),
		OrgID:      org.ID,
		Name:       "Count Test",
		SecretHash: "count-hash-" + uuid.New().String(),
		Active:     true,
	}
	if err := repo.CreateWebhook(ctx, webhook); err != nil {
		t.Fatalf("CreateWebhook failed: %v", err)
	}

	count, err = repo.CountWebhooksByOrg(ctx, org.ID)
	if err != nil {
		t.Fatalf("CountWebhooksByOrg after create failed: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 after create, got %d", count)
	}
}

func TestSbomWebhookRepository_TenantIsolation(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "sbom_webhooks")
	orgA := testutil.CreateTestOrg(t, db)
	orgB := testutil.CreateTestOrg(t, db)
	repo := NewSbomWebhookRepository(db)
	ctx := context.Background()

	webhookA := &models.SbomWebhook{
		ID:         uuid.New(),
		OrgID:      orgA.ID,
		Name:       "Org A Webhook",
		SecretHash: "hash-a-" + uuid.New().String(),
		Active:     true,
	}
	if err := repo.CreateWebhook(ctx, webhookA); err != nil {
		t.Fatalf("CreateWebhook org A failed: %v", err)
	}

	// Org B should not see org A's webhook via ListWebhooksByOrg
	webhooks, err := repo.ListWebhooksByOrg(ctx, orgB.ID, 10, 0)
	if err != nil {
		t.Fatalf("ListWebhooksByOrg org B failed: %v", err)
	}
	if len(webhooks) != 0 {
		t.Errorf("expected 0 webhooks for org B, got %d", len(webhooks))
	}

	// Org B cannot delete org A's webhook (org_id mismatch)
	err = repo.DeleteWebhook(ctx, webhookA.ID, orgB.ID)
	if err != ErrSbomWebhookNotFound {
		t.Errorf("expected ErrSbomWebhookNotFound for cross-tenant delete, got %v", err)
	}
}
