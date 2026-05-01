// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/vincents-ai/transparenz-server-oss/pkg/interfaces"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
	"github.com/vincents-ai/transparenz-server-oss/pkg/repository"
)

var (
	ErrInvalidDisclosureStatus = errors.New("invalid disclosure status")
	ErrDisclosureNotFound      = errors.New("disclosure not found")
)

type DisclosureService struct {
	repo interfaces.DisclosureRepository
}

func NewDisclosureService(repo interfaces.DisclosureRepository) *DisclosureService {
	return &DisclosureService{repo: repo}
}

func (s *DisclosureService) ReceiveDisclosure(ctx context.Context, orgID uuid.UUID, disclosure *models.VulnerabilityDisclosure) (*models.VulnerabilityDisclosure, error) {
	if disclosure.Cve == "" {
		return nil, fmt.Errorf("cve is required")
	}
	if disclosure.Title == "" {
		return nil, fmt.Errorf("title is required")
	}
	if !isValidSeverity(disclosure.Severity) {
		return nil, fmt.Errorf("invalid severity: must be one of low, medium, high, critical")
	}
	if disclosure.Severity == "" {
		disclosure.Severity = "medium"
	}
	disclosure.Status = "received"
	if err := s.repo.Create(ctx, orgID, disclosure); err != nil {
		return nil, fmt.Errorf("failed to create disclosure: %w", err)
	}
	return disclosure, nil
}

func (s *DisclosureService) StartTriaging(ctx context.Context, id uuid.UUID) error {
	return s.repo.UpdateStatus(ctx, id, "triaging")
}

func (s *DisclosureService) AcknowledgeDisclosure(ctx context.Context, id uuid.UUID, coordinatorName, coordinatorEmail string) error {
	disclosure, err := s.repo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrDisclosureNotFound) {
			return ErrDisclosureNotFound
		}
		return err
	}
	disclosure.CoordinatorName = coordinatorName
	disclosure.CoordinatorEmail = coordinatorEmail
	if err := s.repo.Update(ctx, disclosure); err != nil {
		return err
	}
	return s.repo.UpdateStatus(ctx, id, "acknowledged")
}

func (s *DisclosureService) StartFixing(ctx context.Context, id uuid.UUID) error {
	return s.repo.UpdateStatus(ctx, id, "fixing")
}

func (s *DisclosureService) MarkFixed(ctx context.Context, id uuid.UUID, fixCommit, fixVersion string) error {
	disclosure, err := s.repo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrDisclosureNotFound) {
			return ErrDisclosureNotFound
		}
		return err
	}
	disclosure.FixCommit = fixCommit
	disclosure.FixVersion = fixVersion
	if err := s.repo.Update(ctx, disclosure); err != nil {
		return err
	}
	return s.repo.UpdateStatus(ctx, id, "fixed")
}

func (s *DisclosureService) Disclose(ctx context.Context, id uuid.UUID) error {
	return s.repo.UpdateStatus(ctx, id, "disclosed")
}

func (s *DisclosureService) RejectDisclosure(ctx context.Context, id uuid.UUID, internalNotes string) error {
	disclosure, err := s.repo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrDisclosureNotFound) {
			return ErrDisclosureNotFound
		}
		return err
	}
	disclosure.InternalNotes = internalNotes
	if err := s.repo.Update(ctx, disclosure); err != nil {
		return err
	}
	return s.repo.UpdateStatus(ctx, id, "rejected")
}

func (s *DisclosureService) WithdrawDisclosure(ctx context.Context, id uuid.UUID) error {
	return s.repo.UpdateStatus(ctx, id, "withdrawn")
}

func (s *DisclosureService) GetByID(ctx context.Context, id uuid.UUID) (*models.VulnerabilityDisclosure, error) {
	disclosure, err := s.repo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrDisclosureNotFound) {
			return nil, ErrDisclosureNotFound
		}
		return nil, err
	}
	return disclosure, nil
}

func (s *DisclosureService) ListByOrg(ctx context.Context, limit, offset int) ([]models.VulnerabilityDisclosure, error) {
	return s.repo.List(ctx, limit, offset)
}

func (s *DisclosureService) CountByOrg(ctx context.Context) (int64, error) {
	return s.repo.Count(ctx)
}

func (s *DisclosureService) CheckSLACompliance(ctx context.Context) ([]models.VulnerabilityDisclosure, error) {
	var nonTerminal []models.VulnerabilityDisclosure
	var err error
	for _, status := range []string{"received", "triaging", "acknowledged", "fixing"} {
		items, listErr := s.repo.ListByStatus(ctx, status, 0, 0)
		if listErr != nil {
			err = listErr
			continue
		}
		nonTerminal = append(nonTerminal, items...)
	}
	if err != nil {
		return nil, err
	}

	now := time.Now()
	var violations []models.VulnerabilityDisclosure
	for i := range nonTerminal {
		d := &nonTerminal[i]
		if isSLABreached(d, now) {
			violations = append(violations, *d)
		}
	}
	return violations, nil
}

func isSLABreached(d *models.VulnerabilityDisclosure, now time.Time) bool {
	switch d.Status {
	case "received", "triaging":
		return now.Sub(d.ReceivedAt) > 7*24*time.Hour
	case "acknowledged":
		deadline := 180 * 24 * time.Hour
		if d.Severity == "critical" {
			deadline = 90 * 24 * time.Hour
		}
		if d.AcknowledgedAt != nil {
			return now.Sub(*d.AcknowledgedAt) > deadline
		}
		return now.Sub(d.ReceivedAt) > 7*24*time.Hour+deadline
	case "fixing":
		deadline := 180 * 24 * time.Hour
		if d.Severity == "critical" {
			deadline = 90 * 24 * time.Hour
		}
		base := d.ReceivedAt
		if d.AcknowledgedAt != nil {
			base = *d.AcknowledgedAt
		}
		return now.Sub(base) > deadline
	}
	return false
}

func isValidSeverity(s string) bool {
	switch s {
	case "low", "medium", "high", "critical", "":
		return true
	}
	return false
}
