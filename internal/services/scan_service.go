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
	"github.com/transparenz/transparenz-server-oss/internal/interfaces"
	"github.com/transparenz/transparenz-server-oss/internal/models"
	"github.com/transparenz/transparenz-server-oss/internal/repository"
)

var (
	ErrSbomNotFound    = errors.New("SBOM not found")
	ErrScanNotFound    = errors.New("scan not found")
	ErrFailedToCreate  = errors.New("failed to create scan")
	ErrFailedToList    = errors.New("failed to list scans")
	ErrFailedToGetScan = errors.New("failed to get scan")
)

// ScanService orchestrates vulnerability scan creation and lifecycle management.
type ScanService struct {
	scanRepo   interfaces.ScanRepository
	sbomRepo   interfaces.SbomRepository
	scanWorker interfaces.ScanWorker
}

func NewScanService(
	scanRepo interfaces.ScanRepository,
	sbomRepo interfaces.SbomRepository,
	scanWorker interfaces.ScanWorker,
) *ScanService {
	return &ScanService{
		scanRepo:   scanRepo,
		sbomRepo:   sbomRepo,
		scanWorker: scanWorker,
	}
}

func (s *ScanService) CreateScan(ctx context.Context, orgID uuid.UUID, sbomID uuid.UUID) (*models.Scan, error) {
	exists, err := s.sbomRepo.ExistsByID(ctx, sbomID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFailedToCreate, err)
	}
	if !exists {
		return nil, ErrSbomNotFound
	}

	scan := &models.Scan{
		OrgID:  orgID,
		SbomID: sbomID,
		Status: "pending",
	}

	if err := s.scanRepo.Create(ctx, orgID, scan); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFailedToCreate, err)
	}

	if err := s.scanWorker.EnqueueScan(ctx, scan.ID, orgID, sbomID); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFailedToCreate, err)
	}

	return scan, nil
}

func (s *ScanService) CountScans(ctx context.Context) (int64, error) {
	count, err := s.scanRepo.Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrFailedToList, err)
	}
	return count, nil
}

func (s *ScanService) ListScans(ctx context.Context, limit, offset int) ([]models.Scan, error) {
	scans, err := s.scanRepo.List(ctx, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFailedToList, err)
	}
	return scans, nil
}

func (s *ScanService) GetScan(ctx context.Context, id uuid.UUID) (*models.Scan, error) {
	scan, err := s.scanRepo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrScanNotFound) {
			return nil, ErrScanNotFound
		}
		return nil, fmt.Errorf("%w: %w", ErrFailedToGetScan, err)
	}
	return scan, nil
}
