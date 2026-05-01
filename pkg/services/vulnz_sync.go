// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package services

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/vincents-ai/vulnz/pkg/api"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
	"github.com/vincents-ai/transparenz-server-oss/pkg/repository"
	"go.uber.org/zap"
	"gorm.io/datatypes"
)

// VulnzFeedSource is the testable seam for the EU vulnerability feed. Any
// implementation that can return a slice of FetchResult is accepted; the
// default production implementation delegates to api.FetchEUFeeds.
type VulnzFeedSource interface {
	FetchEUFeeds(ctx context.Context, providers []string) ([]api.FetchResult, error)
}

// realVulnzFeedSource wraps the real api.FetchEUFeeds function so it satisfies
// VulnzFeedSource.
type realVulnzFeedSource struct{}

func (realVulnzFeedSource) FetchEUFeeds(ctx context.Context, providers []string) ([]api.FetchResult, error) {
	return api.FetchEUFeeds(ctx, providers)
}

// NewRealVulnzFeedSource returns the production feed source backed by the
// vulnz-go library.
func NewRealVulnzFeedSource() VulnzFeedSource {
	return realVulnzFeedSource{}
}

type VulnzSyncService struct {
	feedRepo     *repository.VulnerabilityFeedRepository
	feedSource   VulnzFeedSource
	syncInterval time.Duration
	logger       *zap.Logger
	stopCh       chan struct{}
}

// NewVulnzSyncService constructs a VulnzSyncService.  feedSource is the
// injectable feed backend; pass NewRealVulnzFeedSource() for production.
func NewVulnzSyncService(feedRepo *repository.VulnerabilityFeedRepository, feedSource VulnzFeedSource, syncInterval time.Duration, logger *zap.Logger) *VulnzSyncService {
	return &VulnzSyncService{
		feedRepo:     feedRepo,
		feedSource:   feedSource,
		syncInterval: syncInterval,
		logger:       logger,
		stopCh:       make(chan struct{}),
	}
}

func (s *VulnzSyncService) SyncAll(ctx context.Context) error {
	s.logger.Info("starting vulnz sync via vulnz-go library")

	syncStart := time.Now()

	results, err := s.feedSource.FetchEUFeeds(ctx, []string{"euvd", "bsi-cert-bund", "kev"})
	if err != nil {
		s.logger.Error("vulnz sync failed", zap.Error(err))
		return err
	}

	var totalSynced, totalErrors int

	for _, result := range results {
		synced, errors := s.upsertRecords(ctx, result.Records)
		s.logger.Info("provider sync completed",
			zap.String("provider", result.Provider),
			zap.Int("synced", synced),
			zap.Int("errors", errors),
		)
		totalSynced += synced
		totalErrors += errors
	}

	s.logger.Info("vulnz sync completed",
		zap.Duration("duration", time.Since(syncStart)),
		zap.Int("total_synced", totalSynced),
		zap.Int("total_errors", totalErrors),
	)

	return nil
}

func (s *VulnzSyncService) upsertRecords(ctx context.Context, records []api.FeedRecord) (int, int) {
	var synced, errors int

	for _, record := range records {
		apJSON, err := json.Marshal(record.AffectedProducts)
		if err != nil {
			s.logger.Error("failed to marshal affected products",
				zap.String("cve", record.Cve),
				zap.Error(err),
			)
			errors++
			continue
		}

		feed := &models.VulnerabilityFeed{
			ID:                  uuid.New(),
			Cve:                 record.Cve,
			KevExploited:        record.KevExploited,
			KevDateAdded:        record.KevDateAdded,
			EnisaEuvdID:         record.EnisaEuvdID,
			EnisaSeverity:       record.EnisaSeverity,
			BsiAdvisoryID:       record.BsiAdvisoryID,
			BsiTr03116Compliant: record.BsiTr03116Compliant,
			AffectedProducts:    datatypes.JSON(apJSON),
			LastSyncedAt:        time.Now(),
		}

		if err := s.feedRepo.Upsert(ctx, feed); err != nil {
			s.logger.Error("failed to upsert feed record",
				zap.String("cve", feed.Cve),
				zap.String("provider", record.Provider),
				zap.Error(err),
			)
			errors++
			continue
		}
		synced++
	}

	return synced, errors
}

func (s *VulnzSyncService) Start(ctx context.Context) {
	s.logger.Info("starting vulnz sync service",
		zap.Duration("interval", s.syncInterval),
	)

	if err := s.SyncAll(ctx); err != nil {
		s.logger.Error("initial vulnz sync failed", zap.Error(err))
	}

	ticker := time.NewTicker(s.syncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := s.SyncAll(ctx); err != nil {
				s.logger.Error("scheduled vulnz sync failed", zap.Error(err))
			}
		case <-s.stopCh:
			s.logger.Info("vulnz sync service stopped")
			return
		case <-ctx.Done():
			s.logger.Info("vulnz sync service context cancelled")
			return
		}
	}
}

func (s *VulnzSyncService) Stop() {
	close(s.stopCh)
}
