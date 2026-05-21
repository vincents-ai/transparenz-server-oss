package repository

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestOrganizationRepository(t *testing.T) {
	db := setupTestDB(t)
	repo := NewOrganizationRepository(db)
	ctx := context.Background()

	t.Run("create and get by id", func(t *testing.T) {
		org := &models.Organization{
			ID:                  uuid.New(),
			Name:                "Test Org",
			Slug:                "test-org-" + uuid.New().String()[:8],
			EnisaSubmissionMode: "export",
			CsafScope:           "per_sbom",
			PdfTemplate:         "generic",
			SlaTrackingMode:     "per_cve",
		}

		err := repo.Create(ctx, org)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}

		found, err := repo.GetByID(ctx, org.ID)
		if err != nil {
			t.Fatalf("GetByID failed: %v", err)
		}
		if found.Name != org.Name {
			t.Errorf("Name = %q, want %q", found.Name, org.Name)
		}
		if found.Slug != org.Slug {
			t.Errorf("Slug = %q, want %q", found.Slug, org.Slug)
		}
	})

	t.Run("get by slug", func(t *testing.T) {
		org := &models.Organization{
			ID:                  uuid.New(),
			Name:                "Slug Test Org",
			Slug:                "slug-test-" + uuid.New().String()[:8],
			EnisaSubmissionMode: "export",
			CsafScope:           "per_sbom",
			PdfTemplate:         "generic",
			SlaTrackingMode:     "per_cve",
		}

		err := repo.Create(ctx, org)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}

		found, err := repo.GetBySlug(ctx, org.Slug)
		if err != nil {
			t.Fatalf("GetBySlug failed: %v", err)
		}
		if found.ID != org.ID {
			t.Errorf("ID = %v, want %v", found.ID, org.ID)
		}
	})

	t.Run("get by id not found", func(t *testing.T) {
		_, err := repo.GetByID(ctx, uuid.New())
		if err != ErrOrganizationNotFound {
			t.Errorf("expected ErrOrganizationNotFound, got %v", err)
		}
	})

	t.Run("get by slug not found", func(t *testing.T) {
		_, err := repo.GetBySlug(ctx, "nonexistent-slug")
		if err != ErrOrganizationNotFound {
			t.Errorf("expected ErrOrganizationNotFound, got %v", err)
		}
	})

	t.Run("update", func(t *testing.T) {
		org := &models.Organization{
			ID:                  uuid.New(),
			Name:                "Before Update",
			Slug:                "update-test-" + uuid.New().String()[:8],
			EnisaSubmissionMode: "export",
			CsafScope:           "per_sbom",
			PdfTemplate:         "generic",
			SlaTrackingMode:     "per_cve",
		}

		err := repo.Create(ctx, org)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}

		org.Name = "After Update"
		err = repo.Update(ctx, org)
		if err != nil {
			t.Fatalf("Update failed: %v", err)
		}

		found, err := repo.GetByID(ctx, org.ID)
		if err != nil {
			t.Fatalf("GetByID failed: %v", err)
		}
		if found.Name != "After Update" {
			t.Errorf("Name = %q, want %q", found.Name, "After Update")
		}
	})

	t.Run("delete", func(t *testing.T) {
		org := &models.Organization{
			ID:                  uuid.New(),
			Name:                "To Delete",
			Slug:                "delete-test-" + uuid.New().String()[:8],
			EnisaSubmissionMode: "export",
			CsafScope:           "per_sbom",
			PdfTemplate:         "generic",
			SlaTrackingMode:     "per_cve",
		}

		err := repo.Create(ctx, org)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}

		err = repo.Delete(ctx, org.ID)
		if err != nil {
			t.Fatalf("Delete failed: %v", err)
		}

		_, err = repo.GetByID(ctx, org.ID)
		if err != ErrOrganizationNotFound {
			t.Errorf("expected ErrOrganizationNotFound after delete, got %v", err)
		}
	})

	t.Run("list all", func(t *testing.T) {
		org := &models.Organization{
			ID:                  uuid.New(),
			Name:                "List Test Org",
			Slug:                "list-test-" + uuid.New().String()[:8],
			EnisaSubmissionMode: "export",
			CsafScope:           "per_sbom",
			PdfTemplate:         "generic",
			SlaTrackingMode:     "per_cve",
		}

		err := repo.Create(ctx, org)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}

		orgs, err := repo.ListAll(ctx)
		if err != nil {
			t.Fatalf("ListAll failed: %v", err)
		}
		if len(orgs) == 0 {
			t.Error("ListAll returned empty list")
		}
	})
}

func setupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := "postgres://user:pass@localhost:5432/transparenz_test?search_path=compliance"
	if d := os.Getenv("TEST_DATABASE_URL"); d != "" {
		dsn = d
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Skipf("test database not available: %v", err)
	}
	t.Cleanup(func() {
		tables := []string{
			"compliance.compliance_events",
			"compliance.sla_tracking",
			"compliance.enisa_submissions",
			"compliance.scans",
			"compliance.vulnerabilities",
			"compliance.organizations",
		}
		for _, table := range tables {
			db.Exec("DELETE FROM " + table)
		}
	})
	return db
}
