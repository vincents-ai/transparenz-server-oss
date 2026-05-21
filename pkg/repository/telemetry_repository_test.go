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

func TestTelemetryRepository_CreateAndGetByOrgID(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "org_telemetry_configs")
	org := testutil.CreateTestOrg(t, db)
	repo := NewTelemetryRepository(db)
	ctx := context.Background()

	config := &models.OrgTelemetryConfig{
		ID:               uuid.New(),
		Provider:         "prometheus",
		MetricsTokenHash: "hash-" + uuid.New().String(),
		Active:           true,
	}

	err := repo.Create(ctx, org.ID, config)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if config.OrgID != org.ID {
		t.Errorf("OrgID = %v, want %v", config.OrgID, org.ID)
	}

	found, err := repo.GetByOrgID(ctx, org.ID)
	if err != nil {
		t.Fatalf("GetByOrgID failed: %v", err)
	}
	if found.Provider != "prometheus" {
		t.Errorf("Provider = %q, want %q", found.Provider, "prometheus")
	}
	if found.OrgID != org.ID {
		t.Errorf("OrgID = %v, want %v", found.OrgID, org.ID)
	}
}

func TestTelemetryRepository_GetByOrgID_NotFound(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "org_telemetry_configs")
	repo := NewTelemetryRepository(db)
	ctx := context.Background()

	_, err := repo.GetByOrgID(ctx, uuid.New())
	if err != ErrTelemetryConfigNotFound {
		t.Errorf("expected ErrTelemetryConfigNotFound, got %v", err)
	}
}

func TestTelemetryRepository_Update(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "org_telemetry_configs")
	org := testutil.CreateTestOrg(t, db)
	repo := NewTelemetryRepository(db)
	ctx := context.Background()

	config := &models.OrgTelemetryConfig{
		ID:               uuid.New(),
		Provider:         "prometheus",
		MetricsTokenHash: "hash-" + uuid.New().String(),
		Active:           true,
	}
	if err := repo.Create(ctx, org.ID, config); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	config.Provider = "otel"
	config.OtelEndpoint = "https://collector.example.com:4317"
	if err := repo.Update(ctx, config); err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	found, err := repo.GetByOrgID(ctx, org.ID)
	if err != nil {
		t.Fatalf("GetByOrgID after update failed: %v", err)
	}
	if found.Provider != "otel" {
		t.Errorf("Provider = %q, want %q", found.Provider, "otel")
	}
	if found.OtelEndpoint != "https://collector.example.com:4317" {
		t.Errorf("OtelEndpoint = %q, want %q", found.OtelEndpoint, "https://collector.example.com:4317")
	}
}

func TestTelemetryRepository_GetByMetricsTokenPrefix(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "org_telemetry_configs")
	org := testutil.CreateTestOrg(t, db)
	repo := NewTelemetryRepository(db)
	ctx := context.Background()

	tokenHash := "metrics-token-" + uuid.New().String()
	tokenPrefix := "prefix123456789" // 16-char prefix
	config := &models.OrgTelemetryConfig{
		ID:                  uuid.New(),
		Provider:            "prometheus",
		MetricsTokenHash:    tokenHash,
		MetricsTokenPrefix:  tokenPrefix,
		Active:              true,
	}
	if err := repo.Create(ctx, org.ID, config); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	found, err := repo.GetByMetricsTokenPrefix(ctx, tokenPrefix)
	if err != nil {
		t.Fatalf("GetByMetricsTokenPrefix failed: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("expected 1 result, got %d", len(found))
	}
	if found[0].OrgID != org.ID {
		t.Errorf("OrgID = %v, want %v", found[0].OrgID, org.ID)
	}
}

func TestTelemetryRepository_GetByMetricsTokenPrefix_NotFound(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "org_telemetry_configs")
	repo := NewTelemetryRepository(db)
	ctx := context.Background()

	found, err := repo.GetByMetricsTokenPrefix(ctx, "nonexistent-prefix")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("expected 0 results, got %d", len(found))
	}
}

func TestTelemetryRepository_GetAllActive(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "org_telemetry_configs")
	repo := NewTelemetryRepository(db)
	ctx := context.Background()

	// create two orgs with configs — one active, one inactive
	orgA := testutil.CreateTestOrg(t, db)
	orgB := testutil.CreateTestOrg(t, db)

	activeConfig := &models.OrgTelemetryConfig{
		ID:               uuid.New(),
		Provider:         "prometheus",
		MetricsTokenHash: "active-hash-" + uuid.New().String(),
		Active:           true,
	}
	inactiveConfig := &models.OrgTelemetryConfig{
		ID:               uuid.New(),
		Provider:         "prometheus",
		MetricsTokenHash: "inactive-hash-" + uuid.New().String(),
		Active:           false,
	}

	if err := repo.Create(ctx, orgA.ID, activeConfig); err != nil {
		t.Fatalf("Create active config failed: %v", err)
	}
	if err := repo.Create(ctx, orgB.ID, inactiveConfig); err != nil {
		t.Fatalf("Create inactive config failed: %v", err)
	}

	// GetAllActive uses WHERE active = true; SQLite stores bool as 1/0
	// This tests that the query runs without error
	configs, err := repo.GetAllActive(ctx)
	if err != nil {
		t.Fatalf("GetAllActive failed: %v", err)
	}
	for _, c := range configs {
		if !c.Active {
			t.Errorf("GetAllActive returned inactive config: %v", c.ID)
		}
	}
}
