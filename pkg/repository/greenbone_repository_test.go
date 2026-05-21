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

func TestGreenboneRepository_CreateAndGetWebhookByID(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "greenbone_webhooks")
	org := testutil.CreateTestOrg(t, db)
	repo := NewGreenboneRepository(db)
	ctx := context.Background()

	webhook := &models.GreenboneWebhook{
		ID:         uuid.New(),
		OrgID:      org.ID,
		Name:       "Test Greenbone Webhook",
		SecretHash: "secret-" + uuid.New().String(),
		Active:     true,
		Actions: models.GreenboneWebhookActions{
			StoreFindings:   true,
			BroadcastAlerts: true,
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
	if found.Name != "Test Greenbone Webhook" {
		t.Errorf("Name = %q, want %q", found.Name, "Test Greenbone Webhook")
	}
	if found.OrgID != org.ID {
		t.Errorf("OrgID = %v, want %v", found.OrgID, org.ID)
	}
}

func TestGreenboneRepository_GetWebhookByID_NotFound(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "greenbone_webhooks")
	repo := NewGreenboneRepository(db)
	ctx := context.Background()

	_, err := repo.GetWebhookByID(ctx, uuid.New())
	if err != ErrWebhookNotFound {
		t.Errorf("expected ErrWebhookNotFound, got %v", err)
	}
}

func TestGreenboneRepository_ListWebhooksByOrg(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "greenbone_webhooks")
	org := testutil.CreateTestOrg(t, db)
	repo := NewGreenboneRepository(db)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		wh := &models.GreenboneWebhook{
			ID:         uuid.New(),
			OrgID:      org.ID,
			Name:       "GVM Webhook " + string(rune('A'+i)),
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
		t.Errorf("expected 2 with limit, got %d", len(limited))
	}
}

func TestGreenboneRepository_DeleteWebhook(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "greenbone_webhooks")
	org := testutil.CreateTestOrg(t, db)
	repo := NewGreenboneRepository(db)
	ctx := context.Background()

	webhook := &models.GreenboneWebhook{
		ID:         uuid.New(),
		OrgID:      org.ID,
		Name:       "To Delete",
		SecretHash: "del-hash-" + uuid.New().String(),
		Active:     true,
	}
	if err := repo.CreateWebhook(ctx, webhook); err != nil {
		t.Fatalf("CreateWebhook failed: %v", err)
	}

	if err := repo.DeleteWebhook(ctx, webhook.ID, org.ID); err != nil {
		t.Fatalf("DeleteWebhook failed: %v", err)
	}

	_, err := repo.GetWebhookByID(ctx, webhook.ID)
	if err != ErrWebhookNotFound {
		t.Errorf("expected ErrWebhookNotFound after delete, got %v", err)
	}
}

func TestGreenboneRepository_DeleteWebhook_NotFound(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "greenbone_webhooks")
	org := testutil.CreateTestOrg(t, db)
	repo := NewGreenboneRepository(db)
	ctx := context.Background()

	err := repo.DeleteWebhook(ctx, uuid.New(), org.ID)
	if err != ErrWebhookNotFound {
		t.Errorf("expected ErrWebhookNotFound, got %v", err)
	}
}

func TestGreenboneRepository_CountWebhooksByOrg(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "greenbone_webhooks")
	org := testutil.CreateTestOrg(t, db)
	repo := NewGreenboneRepository(db)
	ctx := context.Background()

	count, err := repo.CountWebhooksByOrg(ctx, org.ID)
	if err != nil {
		t.Fatalf("CountWebhooksByOrg failed: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 initial count, got %d", count)
	}

	webhook := &models.GreenboneWebhook{
		ID:         uuid.New(),
		OrgID:      org.ID,
		Name:       "Count Webhook",
		SecretHash: "cnt-hash-" + uuid.New().String(),
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

func TestGreenboneRepository_TenantIsolation(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "greenbone_webhooks")
	orgA := testutil.CreateTestOrg(t, db)
	orgB := testutil.CreateTestOrg(t, db)
	repo := NewGreenboneRepository(db)
	ctx := context.Background()

	webhookA := &models.GreenboneWebhook{
		ID:         uuid.New(),
		OrgID:      orgA.ID,
		Name:       "Org A GVM Webhook",
		SecretHash: "hash-a-" + uuid.New().String(),
		Active:     true,
	}
	if err := repo.CreateWebhook(ctx, webhookA); err != nil {
		t.Fatalf("CreateWebhook org A failed: %v", err)
	}

	webhooks, err := repo.ListWebhooksByOrg(ctx, orgB.ID, 10, 0)
	if err != nil {
		t.Fatalf("ListWebhooksByOrg org B failed: %v", err)
	}
	if len(webhooks) != 0 {
		t.Errorf("expected 0 webhooks for org B, got %d", len(webhooks))
	}

	// Cross-tenant delete should fail
	err = repo.DeleteWebhook(ctx, webhookA.ID, orgB.ID)
	if err != ErrWebhookNotFound {
		t.Errorf("expected ErrWebhookNotFound for cross-tenant delete, got %v", err)
	}
}
