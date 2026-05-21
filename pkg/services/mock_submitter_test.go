package services

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
)

func TestMockENISASubmitter_Submit(t *testing.T) {
	m := NewMockENISASubmitter()
	orgID := uuid.New()
	csaf := models.JSONMap{"document": map[string]interface{}{"title": "test"}}

	sub, err := m.Submit(context.Background(), orgID, "CVE-2024-0001", csaf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if sub.ID == uuid.Nil {
		t.Error("expected non-zero submission ID")
	}

	if sub.OrgID != orgID {
		t.Errorf("expected org ID %s, got %s", orgID, sub.OrgID)
	}

	if !strings.HasPrefix(sub.SubmissionID, "MOCK-") {
		t.Errorf("expected submission ID to start with MOCK-, got %s", sub.SubmissionID)
	}

	if sub.Status != "submitted" {
		t.Errorf("expected status 'submitted', got %s", sub.Status)
	}

	if sub.CsafDocument == nil {
		t.Error("expected non-nil CSAF document")
	}
}

func TestMockENISASubmitter_GetRecords(t *testing.T) {
	m := NewMockENISASubmitter()
	orgID := uuid.New()
	csaf := models.JSONMap{"key": "value"}

	records := m.GetRecords()
	if len(records) != 0 {
		t.Fatalf("expected 0 records, got %d", len(records))
	}

	_, _ = m.Submit(context.Background(), orgID, "CVE-2024-0001", csaf)
	_, _ = m.Submit(context.Background(), orgID, "CVE-2024-0002", csaf)

	records = m.GetRecords()
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}

	if records[0].CVE != "CVE-2024-0001" {
		t.Errorf("expected first CVE CVE-2024-0001, got %s", records[0].CVE)
	}

	if records[1].CVE != "CVE-2024-0002" {
		t.Errorf("expected second CVE CVE-2024-0002, got %s", records[1].CVE)
	}
}

func TestMockENISASubmitter_GetRecords_ReturnsCopy(t *testing.T) {
	m := NewMockENISASubmitter()
	orgID := uuid.New()
	csaf := models.JSONMap{"key": "value"}

	_, _ = m.Submit(context.Background(), orgID, "CVE-2024-0001", csaf)

	records := m.GetRecords()
	records[0].CVE = "MUTATED"

	records2 := m.GetRecords()
	if records2[0].CVE == "MUTATED" {
		t.Error("GetRecords should return a copy, not a reference to internal slice")
	}
}

func TestMockENISASubmitter_Reset(t *testing.T) {
	m := NewMockENISASubmitter()
	orgID := uuid.New()
	csaf := models.JSONMap{"key": "value"}

	_, _ = m.Submit(context.Background(), orgID, "CVE-2024-0001", csaf)
	_, _ = m.Submit(context.Background(), orgID, "CVE-2024-0002", csaf)

	if len(m.GetRecords()) != 2 {
		t.Fatalf("expected 2 records before reset")
	}

	m.Reset()

	if len(m.GetRecords()) != 0 {
		t.Fatalf("expected 0 records after reset, got %d", len(m.GetRecords()))
	}
}

func TestMockENISASubmitter_SubmitMultiple(t *testing.T) {
	m := NewMockENISASubmitter()
	orgID := uuid.New()
	csaf := models.JSONMap{}

	sub1, _ := m.Submit(context.Background(), orgID, "CVE-2024-0001", csaf)
	sub2, _ := m.Submit(context.Background(), orgID, "CVE-2024-0002", csaf)

	if sub1.ID == sub2.ID {
		t.Error("expected unique submission IDs")
	}

	if sub1.SubmissionID == sub2.SubmissionID {
		t.Error("expected unique submission external IDs")
	}

	records := m.GetRecords()
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
}
