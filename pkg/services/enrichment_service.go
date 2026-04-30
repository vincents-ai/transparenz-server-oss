// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package services

import (
	"context"
	"fmt"
	"sync"

	"github.com/shift/enrichment-engine/pkg/enricher"
	"github.com/shift/enrichment-engine/pkg/storage"
	"go.uber.org/zap"
)

type EnrichmentService struct {
	store           storage.Backend
	dbPath          string
	providersLoaded bool
	mu              sync.RWMutex
	logger          *zap.Logger
}

func NewEnrichmentService(dbPath string, logger *zap.Logger) (*EnrichmentService, error) {
	store, err := storage.NewSQLiteBackend(dbPath)
	if err != nil {
		return nil, fmt.Errorf("create enrichment SQLite backend: %w", err)
	}

	return &EnrichmentService{
		store:  store,
		dbPath: dbPath,
		logger: logger,
	}, nil
}

func (s *EnrichmentService) Initialize(ctx context.Context) error {
	s.logger.Info("initializing enrichment providers")
	engine := enricher.New(enricher.Config{
		Store:       s.store,
		RunAll:      true,
		MaxParallel: 4,
	})

	result, err := engine.Run(ctx)
	if err != nil {
		return fmt.Errorf("enrichment engine run: %w", err)
	}

	s.mu.Lock()
	s.providersLoaded = true
	s.mu.Unlock()

	s.logger.Info("enrichment providers initialized",
		zap.Int("providers", result.ProviderCount),
		zap.Int("controls", result.ControlCount),
		zap.Duration("duration", result.Duration),
	)
	return nil
}

func (s *EnrichmentService) EnrichVulnerability(ctx context.Context, vulnID string, record interface{}) ([]storage.MappingRow, error) {
	s.mu.RLock()
	ready := s.providersLoaded
	s.mu.RUnlock()

	if !ready {
		s.logger.Debug("enrichment providers not yet loaded, returning empty mappings")
		return nil, nil
	}

	if err := s.store.WriteVulnerability(ctx, vulnID, record); err != nil {
		return nil, fmt.Errorf("write vulnerability to enrichment store: %w", err)
	}

	engine := enricher.New(enricher.Config{
		Store:         s.store,
		SkipProviders: true,
		SkipMapping:   false,
	})

	_, err := engine.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("enrichment engine run: %w", err)
	}

	return s.store.ListMappings(ctx, vulnID)
}

func (s *EnrichmentService) IsReady() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.providersLoaded
}

func (s *EnrichmentService) Close(ctx context.Context) error {
	s.logger.Info("closing enrichment service")
	return s.store.Close(ctx)
}
