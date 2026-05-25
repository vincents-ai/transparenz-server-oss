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

// PostSyncHook is called after a successful feed sync.  Implementations
// can use the sync result to trigger follow-up actions (e.g. auto-rescan).
type PostSyncHook interface {
	OnSyncComplete(ctx context.Context, result SyncResult) error
}

// SyncResult contains the outcome of a feed sync cycle.
type SyncResult struct {
	// SyncedCVEs is the set of CVEs that were upserted during this sync.
	SyncedCVEs []SyncedCVE
	// Duration is how long the entire sync took.
	Duration time.Duration
	// TotalSynced is the total number of records upserted.
	TotalSynced int
	// TotalErrors is the total number of upsert errors.
	TotalErrors int
}

// SyncedCVE represents a single CVE that was synced, with its affected products.
type SyncedCVE struct {
	CVE              string
	KevExploited     bool
	AffectedProducts []api.AffectedProduct
}

type VulnzSyncService struct {
	feedRepo     *repository.VulnerabilityFeedRepository
	feedSource   VulnzFeedSource
	syncInterval time.Duration
	logger       *zap.Logger
	stopCh       chan struct{}
	postSyncHook PostSyncHook
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

// SetPostSyncHook registers a hook that is called after each successful sync.
func (s *VulnzSyncService) SetPostSyncHook(hook PostSyncHook) {
	s.postSyncHook = hook
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
	var syncedCVEs []SyncedCVE

	for _, result := range results {
		synced, errors, cves := s.upsertRecords(ctx, result.Records)
		syncedCVEs = append(syncedCVEs, cves...)
		s.logger.Info("provider sync completed",
			zap.String("provider", result.Provider),
			zap.Int("synced", synced),
			zap.Int("errors", errors),
		)
		totalSynced += synced
		totalErrors += errors
	}

	syncResult := SyncResult{
		SyncedCVEs:   syncedCVEs,
		Duration:     time.Since(syncStart),
		TotalSynced:  totalSynced,
		TotalErrors:  totalErrors,
	}

	s.logger.Info("vulnz sync completed",
		zap.Duration("duration", syncResult.Duration),
		zap.Int("total_synced", totalSynced),
		zap.Int("total_errors", totalErrors),
	)

	// Fire post-sync hook if registered
	if s.postSyncHook != nil && len(syncedCVEs) > 0 {
		if err := s.postSyncHook.OnSyncComplete(ctx, syncResult); err != nil {
			s.logger.Error("post-sync hook failed", zap.Error(err))
		}
	}

	return nil
}

func (s *VulnzSyncService) upsertRecords(ctx context.Context, records []api.FeedRecord) (int, int, []SyncedCVE) {
	var synced, errors int
	var syncedCVEs []SyncedCVE

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
		syncedCVEs = append(syncedCVEs, SyncedCVE{
			CVE:              record.Cve,
			KevExploited:     record.KevExploited,
			AffectedProducts: record.AffectedProducts,
		})
	}

	return synced, errors, syncedCVEs
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
