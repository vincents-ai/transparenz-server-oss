// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package services

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
)

type mockDisclosureRepo struct {
	disclosures map[uuid.UUID]*models.VulnerabilityDisclosure
}

func newMockDisclosureRepo() *mockDisclosureRepo {
	return &mockDisclosureRepo{
		disclosures: make(map[uuid.UUID]*models.VulnerabilityDisclosure),
	}
}

func (m *mockDisclosureRepo) Create(_ context.Context, _ uuid.UUID, d *models.VulnerabilityDisclosure) error {
	if d.ID == uuid.Nil {
		d.ID = uuid.New()
	}
	if d.ReceivedAt.IsZero() {
		d.ReceivedAt = time.Now()
	}
	if d.Status == "" {
		d.Status = "received"
	}
	m.disclosures[d.ID] = d
	return nil
}

func (m *mockDisclosureRepo) GetByID(_ context.Context, id uuid.UUID) (*models.VulnerabilityDisclosure, error) {
	d, ok := m.disclosures[id]
	if !ok {
		return nil, ErrDisclosureNotFound
	}
	return d, nil
}

func (m *mockDisclosureRepo) List(_ context.Context, limit, offset int) ([]models.VulnerabilityDisclosure, error) {
	var result []models.VulnerabilityDisclosure
	for _, d := range m.disclosures {
		result = append(result, *d)
	}
	if offset > len(result) {
		return nil, nil
	}
	if limit > 0 && limit < len(result) {
		result = result[:limit]
	}
	return result, nil
}

func (m *mockDisclosureRepo) ListByStatus(_ context.Context, status string, _, _ int) ([]models.VulnerabilityDisclosure, error) {
	var result []models.VulnerabilityDisclosure
	for _, d := range m.disclosures {
		if d.Status == status {
			result = append(result, *d)
		}
	}
	return result, nil
}

func (m *mockDisclosureRepo) ListByCVE(_ context.Context, _ string) ([]models.VulnerabilityDisclosure, error) {
	return nil, nil
}

func (m *mockDisclosureRepo) UpdateStatus(_ context.Context, id uuid.UUID, status string) error {
	d, ok := m.disclosures[id]
	if !ok {
		return ErrDisclosureNotFound
	}
	d.Status = status
	now := time.Now()
	switch status {
	case "acknowledged":
		d.AcknowledgedAt = &now
	case "fixing":
		d.FixingStartedAt = &now
	case "fixed":
		d.FixedAt = &now
	case "disclosed":
		d.DisclosedAt = &now
		d.DisclosureDate = &now
	case "rejected":
		d.RejectedAt = &now
	case "withdrawn":
		d.WithdrawnAt = &now
	}
	return nil
}

func (m *mockDisclosureRepo) Update(_ context.Context, d *models.VulnerabilityDisclosure) error {
	m.disclosures[d.ID] = d
	return nil
}

func (m *mockDisclosureRepo) Count(_ context.Context) (int64, error) {
	return int64(len(m.disclosures)), nil
}

func TestReceiveDisclosure(t *testing.T) {
	repo := newMockDisclosureRepo()
	svc := NewDisclosureService(repo)
	orgID := uuid.New()

	disclosure := &models.VulnerabilityDisclosure{
		Cve:      "CVE-2024-1234",
		Title:    "Test Vulnerability",
		Severity: "high",
	}

	result, err := svc.ReceiveDisclosure(context.Background(), orgID, disclosure)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "received" {
		t.Errorf("expected status received, got %s", result.Status)
	}
	if result.Cve != "CVE-2024-1234" {
		t.Errorf("expected cve CVE-2024-1234, got %s", result.Cve)
	}
}

func TestReceiveDisclosure_MissingFields(t *testing.T) {
	repo := newMockDisclosureRepo()
	svc := NewDisclosureService(repo)
	orgID := uuid.New()

	_, err := svc.ReceiveDisclosure(context.Background(), orgID, &models.VulnerabilityDisclosure{
		Title: "No CVE",
	})
	if err == nil {
		t.Fatal("expected error for missing cve")
	}

	_, err = svc.ReceiveDisclosure(context.Background(), orgID, &models.VulnerabilityDisclosure{
		Cve: "CVE-2024-1234",
	})
	if err == nil {
		t.Fatal("expected error for missing title")
	}
}

func TestReceiveDisclosure_InvalidSeverity(t *testing.T) {
	repo := newMockDisclosureRepo()
	svc := NewDisclosureService(repo)
	orgID := uuid.New()

	_, err := svc.ReceiveDisclosure(context.Background(), orgID, &models.VulnerabilityDisclosure{
		Cve:      "CVE-2024-1234",
		Title:    "Test",
		Severity: "invalid",
	})
	if err == nil {
		t.Fatal("expected error for invalid severity")
	}
}

func TestFullLifecycle(t *testing.T) {
	repo := newMockDisclosureRepo()
	svc := NewDisclosureService(repo)
	orgID := uuid.New()

	disclosure := &models.VulnerabilityDisclosure{
		Cve:      "CVE-2024-5678",
		Title:    "Full Lifecycle Test",
		Severity: "critical",
	}

	created, err := svc.ReceiveDisclosure(context.Background(), orgID, disclosure)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if created.Status != "received" {
		t.Fatalf("expected received, got %s", created.Status)
	}

	err = svc.StartTriaging(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("triage: %v", err)
	}
	updated, _ := repo.GetByID(context.Background(), created.ID)
	if updated.Status != "triaging" {
		t.Fatalf("expected triaging, got %s", updated.Status)
	}

	err = svc.AcknowledgeDisclosure(context.Background(), created.ID, "Alice", "alice@example.com")
	if err != nil {
		t.Fatalf("acknowledge: %v", err)
	}
	updated, _ = repo.GetByID(context.Background(), created.ID)
	if updated.Status != "acknowledged" {
		t.Fatalf("expected acknowledged, got %s", updated.Status)
	}
	if updated.CoordinatorName != "Alice" {
		t.Fatalf("expected coordinator Alice, got %s", updated.CoordinatorName)
	}
	if updated.AcknowledgedAt == nil {
		t.Fatal("expected acknowledged_at to be set")
	}

	err = svc.StartFixing(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("fix: %v", err)
	}
	updated, _ = repo.GetByID(context.Background(), created.ID)
	if updated.Status != "fixing" {
		t.Fatalf("expected fixing, got %s", updated.Status)
	}

	err = svc.MarkFixed(context.Background(), created.ID, "abc123", "v2.0.1")
	if err != nil {
		t.Fatalf("mark fixed: %v", err)
	}
	updated, _ = repo.GetByID(context.Background(), created.ID)
	if updated.Status != "fixed" {
		t.Fatalf("expected fixed, got %s", updated.Status)
	}
	if updated.FixCommit != "abc123" {
		t.Fatalf("expected fix_commit abc123, got %s", updated.FixCommit)
	}
	if updated.FixedAt == nil {
		t.Fatal("expected fixed_at to be set")
	}

	err = svc.Disclose(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("disclose: %v", err)
	}
	updated, _ = repo.GetByID(context.Background(), created.ID)
	if updated.Status != "disclosed" {
		t.Fatalf("expected disclosed, got %s", updated.Status)
	}
	if updated.DisclosedAt == nil {
		t.Fatal("expected disclosed_at to be set")
	}
	if updated.DisclosureDate == nil {
		t.Fatal("expected disclosure_date to be set")
	}
}

func TestRejectionFlow(t *testing.T) {
	repo := newMockDisclosureRepo()
	svc := NewDisclosureService(repo)
	orgID := uuid.New()

	created, err := svc.ReceiveDisclosure(context.Background(), orgID, &models.VulnerabilityDisclosure{
		Cve:      "CVE-2024-9999",
		Title:    "Invalid Report",
		Severity: "low",
	})
	if err != nil {
		t.Fatalf("receive: %v", err)
	}

	err = svc.RejectDisclosure(context.Background(), created.ID, "duplicate report")
	if err != nil {
		t.Fatalf("reject: %v", err)
	}
	updated, _ := repo.GetByID(context.Background(), created.ID)
	if updated.Status != "rejected" {
		t.Fatalf("expected rejected, got %s", updated.Status)
	}
	if updated.InternalNotes != "duplicate report" {
		t.Fatalf("expected internal notes, got %s", updated.InternalNotes)
	}
	if updated.RejectedAt == nil {
		t.Fatal("expected rejected_at to be set")
	}
}

func TestSLAComplianceCheck(t *testing.T) {
	repo := newMockDisclosureRepo()
	svc := NewDisclosureService(repo)
	orgID := uuid.New()

	past := time.Now().Add(-8 * 24 * time.Hour)

	disclosure := &models.VulnerabilityDisclosure{
		Cve:        "CVE-2024-SLA1",
		Title:      "SLA Test",
		Severity:   "medium",
		Status:     "received",
		ReceivedAt: past,
	}
	repo.Create(context.Background(), orgID, disclosure)

	violations, err := svc.CheckSLACompliance(context.Background())
	if err != nil {
		t.Fatalf("check sla: %v", err)
	}

	found := false
	for _, v := range violations {
		if v.ID == disclosure.ID {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected disclosure past 7 days to be in SLA violations")
	}
}

func TestSLACompliance_WithinDeadline(t *testing.T) {
	repo := newMockDisclosureRepo()
	svc := NewDisclosureService(repo)
	orgID := uuid.New()

	disclosure := &models.VulnerabilityDisclosure{
		Cve:        "CVE-2024-SLA2",
		Title:      "SLA Within Test",
		Severity:   "high",
		Status:     "received",
		ReceivedAt: time.Now().Add(-3 * 24 * time.Hour),
	}
	repo.Create(context.Background(), orgID, disclosure)

	violations, err := svc.CheckSLACompliance(context.Background())
	if err != nil {
		t.Fatalf("check sla: %v", err)
	}

	for _, v := range violations {
		if v.ID == disclosure.ID {
			t.Fatal("expected disclosure within 7 days to NOT be in SLA violations")
		}
	}
}

func TestDisclosureNotFound(t *testing.T) {
	repo := newMockDisclosureRepo()
	svc := NewDisclosureService(repo)

	_, err := svc.GetByID(context.Background(), uuid.New())
	if err != ErrDisclosureNotFound {
		t.Fatalf("expected ErrDisclosureNotFound, got %v", err)
	}

	err = svc.StartTriaging(context.Background(), uuid.New())
	if err != ErrDisclosureNotFound {
		t.Fatalf("expected ErrDisclosureNotFound for triage, got %v", err)
	}
}
