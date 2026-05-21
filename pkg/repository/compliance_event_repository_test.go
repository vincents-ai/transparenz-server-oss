package repository

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vincents-ai/transparenz-server-oss/pkg/middleware"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
)

func TestComplianceEventRepository(t *testing.T) {
	db := setupTestDB(t)
	repo := NewComplianceEventRepository(db)

	org := &models.Organization{
		ID:                  uuid.New(),
		Name:                "Event Test Org",
		Slug:                "event-test-" + uuid.New().String()[:8],
		EnisaSubmissionMode: "export",
		CsafScope:           "per_sbom",
		PdfTemplate:         "generic",
		SlaTrackingMode:     "per_cve",
	}
	if err := db.Create(org).Error; err != nil {
		t.Fatalf("failed to create org: %v", err)
	}

	ctx := middleware.ContextWithOrgID(t.Context(), org.ID)

	t.Run("create and list", func(t *testing.T) {
		event := &models.ComplianceEvent{
			ID:        uuid.New(),
			EventType: "sla_breach",
			Severity:  "high",
			Cve:       "CVE-2024-0001",
			Timestamp: time.Now(),
			Metadata:  models.JSONMap{"key": "value"},
		}

		err := repo.Create(ctx, org.ID, event)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}

		events, err := repo.List(ctx, 10, 0)
		if err != nil {
			t.Fatalf("List failed: %v", err)
		}
		if len(events) != 1 {
			t.Fatalf("List returned %d events, want 1", len(events))
		}
		if events[0].Cve != "CVE-2024-0001" {
			t.Errorf("Cve = %q, want %q", events[0].Cve, "CVE-2024-0001")
		}
	})

	t.Run("list by type", func(t *testing.T) {
		event := &models.ComplianceEvent{
			ID:        uuid.New(),
			EventType: "sla_breach",
			Severity:  "critical",
			Cve:       "CVE-2024-0002",
			Timestamp: time.Now(),
		}

		err := repo.Create(ctx, org.ID, event)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}

		events, err := repo.ListByType(ctx, "sla_breach", 10, 0)
		if err != nil {
			t.Fatalf("ListByType failed: %v", err)
		}
		if len(events) == 0 {
			t.Fatal("ListByType returned no events")
		}
		for _, e := range events {
			if e.EventType != "sla_breach" {
				t.Errorf("EventType = %q, want %q", e.EventType, "sla_breach")
			}
		}
	})

	t.Run("list by date range", func(t *testing.T) {
		now := time.Now()
		event := &models.ComplianceEvent{
			ID:        uuid.New(),
			EventType: "enisa_submission",
			Severity:  "low",
			Timestamp: now,
		}

		err := repo.Create(ctx, org.ID, event)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}

		start := now.Add(-1 * time.Hour)
		end := now.Add(1 * time.Hour)
		events, err := repo.ListByDateRange(ctx, start, end)
		if err != nil {
			t.Fatalf("ListByDateRange failed: %v", err)
		}
		if len(events) == 0 {
			t.Fatal("ListByDateRange returned no events")
		}
	})

	t.Run("tenant scope filters by org", func(t *testing.T) {
		otherOrg := &models.Organization{
			ID:                  uuid.New(),
			Name:                "Other Org",
			Slug:                "other-" + uuid.New().String()[:8],
			EnisaSubmissionMode: "export",
			CsafScope:           "per_sbom",
			PdfTemplate:         "generic",
			SlaTrackingMode:     "per_cve",
		}
		if err := db.Create(otherOrg).Error; err != nil {
			t.Fatalf("failed to create other org: %v", err)
		}

		otherCtx := middleware.ContextWithOrgID(t.Context(), otherOrg.ID)

		event := &models.ComplianceEvent{
			ID:        uuid.New(),
			EventType: "notification_sent",
			Severity:  "medium",
			Timestamp: time.Now(),
		}
		if err := repo.Create(otherCtx, otherOrg.ID, event); err != nil {
			t.Fatalf("Create failed: %v", err)
		}

		events, err := repo.List(otherCtx, 10, 0)
		if err != nil {
			t.Fatalf("List failed: %v", err)
		}
		for _, e := range events {
			if e.OrgID != otherOrg.ID {
				t.Errorf("OrgID = %v, want %v", e.OrgID, otherOrg.ID)
			}
		}
	})
}
