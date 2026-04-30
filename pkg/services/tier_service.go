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

	"github.com/google/uuid"
	"github.com/transparenz/transparenz-server-oss/pkg/repository"
	"go.uber.org/zap"
)

var ErrUnknownTier = errors.New("unknown organization tier")

var WebhookLimits = map[string]int{
	"free":         0,
	"starter":      1,
	"standard":     3,
	"professional": 10,
	"enterprise":   -1,
}

type TierService struct {
	greenboneRepo   *repository.GreenboneRepository
	sbomWebhookRepo *repository.SbomWebhookRepository
	logger          *zap.Logger
}

func NewTierService(
	greenboneRepo *repository.GreenboneRepository,
	sbomWebhookRepo *repository.SbomWebhookRepository,
	logger *zap.Logger,
) *TierService {
	return &TierService{
		greenboneRepo:   greenboneRepo,
		sbomWebhookRepo: sbomWebhookRepo,
		logger:          logger,
	}
}

func (s *TierService) CheckGreenboneWebhookLimit(ctx context.Context, orgID uuid.UUID, orgTier string) error {
	limit, ok := WebhookLimits[orgTier]
	if !ok {
		s.logger.Warn("unknown organization tier", zap.String("tier", orgTier), zap.String("org_id", orgID.String()))
		return fmt.Errorf("%w: %s", ErrUnknownTier, orgTier)
	}
	if limit == -1 {
		return nil
	}
	count, err := s.greenboneRepo.CountWebhooksByOrg(ctx, orgID)
	if err != nil {
		return fmt.Errorf("failed to count greenbone webhooks: %w", err)
	}
	if count >= int64(limit) {
		return fmt.Errorf("greenbone webhook limit reached for %s tier (%d max)", orgTier, limit)
	}
	return nil
}

func (s *TierService) CheckSbomWebhookLimit(ctx context.Context, orgID uuid.UUID, orgTier string) error {
	limit, ok := WebhookLimits[orgTier]
	if !ok {
		s.logger.Warn("unknown organization tier", zap.String("tier", orgTier), zap.String("org_id", orgID.String()))
		return fmt.Errorf("%w: %s", ErrUnknownTier, orgTier)
	}
	if limit == -1 {
		return nil
	}
	count, err := s.sbomWebhookRepo.CountWebhooksByOrg(ctx, orgID)
	if err != nil {
		return fmt.Errorf("failed to count sbom webhooks: %w", err)
	}
	if count >= int64(limit) {
		return fmt.Errorf("sbom webhook limit reached for %s tier (%d max)", orgTier, limit)
	}
	return nil
}
