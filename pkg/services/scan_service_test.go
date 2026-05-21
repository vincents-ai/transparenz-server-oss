// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package services

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
	"github.com/vincents-ai/transparenz-server-oss/pkg/repository"
)

// ---------------------------------------------------------------------------
// Mock implementations
// ---------------------------------------------------------------------------

type mockScanRepository struct {
	scans    map[uuid.UUID]*models.Scan
	createFn func(ctx context.Context, orgID uuid.UUID, scan *models.Scan) error
	getFn    func(ctx context.Context, id uuid.UUID) (*models.Scan, error)
	listFn   func(ctx context.Context, limit, offset int) ([]models.Scan, error)
	countFn  func(ctx context.Context) (int64, error)
}

func newMockScanRepository() *mockScanRepository {
	return &mockScanRepository{
		scans: make(map[uuid.UUID]*models.Scan),
	}
}

func (m *mockScanRepository) Create(_ context.Context, orgID uuid.UUID, scan *models.Scan) error {
	if m.createFn != nil {
		return m.createFn(context.Background(), orgID, scan)
	}
	if scan.ID == uuid.Nil {
		scan.ID = uuid.New()
	}
	scan.OrgID = orgID
	m.scans[scan.ID] = scan
	return nil
}

func (m *mockScanRepository) GetByID(_ context.Context, id uuid.UUID) (*models.Scan, error) {
	if m.getFn != nil {
		return m.getFn(context.Background(), id)
	}
	s, ok := m.scans[id]
	if !ok {
		return nil, repository.ErrScanNotFound
	}
	return s, nil
}

func (m *mockScanRepository) List(_ context.Context, limit, offset int) ([]models.Scan, error) {
	if m.listFn != nil {
		return m.listFn(context.Background(), limit, offset)
	}
	var result []models.Scan
	for _, s := range m.scans {
		result = append(result, *s)
	}
	if offset >= len(result) {
		return nil, nil
	}
	result = result[offset:]
	if limit > 0 && limit < len(result) {
		result = result[:limit]
	}
	return result, nil
}

func (m *mockScanRepository) Count(_ context.Context) (int64, error) {
	if m.countFn != nil {
		return m.countFn(context.Background())
	}
	return int64(len(m.scans)), nil
}

type mockSbomRepository struct {
	existsFn func(ctx context.Context, id uuid.UUID) (bool, error)
}

func (m *mockSbomRepository) ExistsByID(_ context.Context, id uuid.UUID) (bool, error) {
	if m.existsFn != nil {
		return m.existsFn(context.Background(), id)
	}
	return true, nil
}

type mockScanWorker struct {
	enqueueFn func(ctx context.Context, scanID, orgID, sbomID uuid.UUID) error
}

func (m *mockScanWorker) EnqueueScan(_ context.Context, scanID, orgID, sbomID uuid.UUID) error {
	if m.enqueueFn != nil {
		return m.enqueueFn(context.Background(), scanID, orgID, sbomID)
	}
	return nil
}

// newTestScanService builds a ScanService with the given mock dependencies.
func newTestScanService(sr *mockScanRepository, sbr *mockSbomRepository, sw *mockScanWorker) *ScanService {
	return &ScanService{
		scanRepo:   sr,
		sbomRepo:   sbr,
		scanWorker: sw,
	}
}

// ---------------------------------------------------------------------------
// CreateScan tests
// ---------------------------------------------------------------------------

func TestCreateScan_Success(t *testing.T) {
	orgID := uuid.New()
	sbomID := uuid.New()

	scanRepo := newMockScanRepository()
	sbomRepo := &mockSbomRepository{}
	worker := &mockScanWorker{}

	svc := newTestScanService(scanRepo, sbomRepo, worker)

	scan, err := svc.CreateScan(context.Background(), orgID, sbomID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if scan == nil {
		t.Fatal("expected non-nil scan")
	}
	if scan.ID == uuid.Nil {
		t.Error("expected scan ID to be set after creation")
	}
	if scan.OrgID != orgID {
		t.Errorf("expected org_id %s, got %s", orgID, scan.OrgID)
	}
	if scan.SbomID != sbomID {
		t.Errorf("expected sbom_id %s, got %s", sbomID, scan.SbomID)
	}
	if scan.Status != "pending" {
		t.Errorf("expected status pending, got %s", scan.Status)
	}
}

func TestCreateScan_SbomNotFound(t *testing.T) {
	orgID := uuid.New()
	sbomID := uuid.New()

	scanRepo := newMockScanRepository()
	sbomRepo := &mockSbomRepository{
		existsFn: func(_ context.Context, _ uuid.UUID) (bool, error) { return false, nil },
	}
	worker := &mockScanWorker{}

	svc := newTestScanService(scanRepo, sbomRepo, worker)

	_, err := svc.CreateScan(context.Background(), orgID, sbomID)
	if !errors.Is(err, ErrSbomNotFound) {
		t.Fatalf("expected ErrSbomNotFound, got %v", err)
	}
}

func TestCreateScan_SbomRepoError(t *testing.T) {
	orgID := uuid.New()
	sbomID := uuid.New()
	repoErr := errors.New("db connection lost")

	scanRepo := newMockScanRepository()
	sbomRepo := &mockSbomRepository{
		existsFn: func(_ context.Context, _ uuid.UUID) (bool, error) { return false, repoErr },
	}
	worker := &mockScanWorker{}

	svc := newTestScanService(scanRepo, sbomRepo, worker)

	_, err := svc.CreateScan(context.Background(), orgID, sbomID)
	if err == nil {
		t.Fatal("expected error propagation from sbom repo")
	}
	if !errors.Is(err, ErrFailedToCreate) {
		t.Errorf("expected wrapped ErrFailedToCreate, got %v", err)
	}
	if !errors.Is(err, repoErr) {
		t.Errorf("expected original repo error to be wrapped, got %v", err)
	}
}

func TestCreateScan_ScanRepoError(t *testing.T) {
	orgID := uuid.New()
	sbomID := uuid.New()
	repoErr := errors.New("insert failed")

	scanRepo := newMockScanRepository()
	scanRepo.createFn = func(_ context.Context, _ uuid.UUID, _ *models.Scan) error {
		return repoErr
	}
	sbomRepo := &mockSbomRepository{}
	worker := &mockScanWorker{}

	svc := newTestScanService(scanRepo, sbomRepo, worker)

	_, err := svc.CreateScan(context.Background(), orgID, sbomID)
	if !errors.Is(err, ErrFailedToCreate) {
		t.Errorf("expected ErrFailedToCreate, got %v", err)
	}
	if !errors.Is(err, repoErr) {
		t.Errorf("expected repo error to be wrapped, got %v", err)
	}
}

func TestCreateScan_WorkerEnqueueError(t *testing.T) {
	orgID := uuid.New()
	sbomID := uuid.New()
	workerErr := errors.New("queue unavailable")

	scanRepo := newMockScanRepository()
	sbomRepo := &mockSbomRepository{}
	worker := &mockScanWorker{
		enqueueFn: func(_ context.Context, _, _, _ uuid.UUID) error { return workerErr },
	}

	svc := newTestScanService(scanRepo, sbomRepo, worker)

	_, err := svc.CreateScan(context.Background(), orgID, sbomID)
	if !errors.Is(err, ErrFailedToCreate) {
		t.Errorf("expected ErrFailedToCreate, got %v", err)
	}
	if !errors.Is(err, workerErr) {
		t.Errorf("expected worker error to be wrapped, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// GetScan tests
// ---------------------------------------------------------------------------

func TestGetScan_Success(t *testing.T) {
	orgID := uuid.New()
	sbomID := uuid.New()
	scanID := uuid.New()

	scanRepo := newMockScanRepository()
	scanRepo.scans[scanID] = &models.Scan{
		ID:     scanID,
		OrgID:  orgID,
		SbomID: sbomID,
		Status: "completed",
	}
	sbomRepo := &mockSbomRepository{}
	worker := &mockScanWorker{}

	svc := newTestScanService(scanRepo, sbomRepo, worker)

	scan, err := svc.GetScan(context.Background(), scanID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if scan.ID != scanID {
		t.Errorf("expected scan ID %s, got %s", scanID, scan.ID)
	}
}

func TestGetScan_NotFound(t *testing.T) {
	scanRepo := newMockScanRepository()
	sbomRepo := &mockSbomRepository{}
	worker := &mockScanWorker{}

	svc := newTestScanService(scanRepo, sbomRepo, worker)

	_, err := svc.GetScan(context.Background(), uuid.New())
	if !errors.Is(err, ErrScanNotFound) {
		t.Fatalf("expected ErrScanNotFound, got %v", err)
	}
}

func TestGetScan_RepoError(t *testing.T) {
	repoErr := errors.New("unexpected db error")

	scanRepo := newMockScanRepository()
	scanRepo.getFn = func(_ context.Context, _ uuid.UUID) (*models.Scan, error) {
		return nil, repoErr
	}
	sbomRepo := &mockSbomRepository{}
	worker := &mockScanWorker{}

	svc := newTestScanService(scanRepo, sbomRepo, worker)

	_, err := svc.GetScan(context.Background(), uuid.New())
	if !errors.Is(err, ErrFailedToGetScan) {
		t.Errorf("expected ErrFailedToGetScan, got %v", err)
	}
	if !errors.Is(err, repoErr) {
		t.Errorf("expected repo error wrapped, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// ListScans tests
// ---------------------------------------------------------------------------

func TestListScans_ReturnsPaginatedResults(t *testing.T) {
	scanRepo := newMockScanRepository()
	orgID := uuid.New()
	for i := 0; i < 5; i++ {
		id := uuid.New()
		scanRepo.scans[id] = &models.Scan{ID: id, OrgID: orgID, Status: "completed"}
	}

	sbomRepo := &mockSbomRepository{}
	worker := &mockScanWorker{}

	svc := newTestScanService(scanRepo, sbomRepo, worker)

	scans, err := svc.ListScans(context.Background(), 3, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(scans) > 3 {
		t.Errorf("expected at most 3 results from limit, got %d", len(scans))
	}
}

func TestListScans_EmptyResult(t *testing.T) {
	scanRepo := newMockScanRepository()
	sbomRepo := &mockSbomRepository{}
	worker := &mockScanWorker{}

	svc := newTestScanService(scanRepo, sbomRepo, worker)

	scans, err := svc.ListScans(context.Background(), 10, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(scans) != 0 {
		t.Errorf("expected empty slice, got %d", len(scans))
	}
}

func TestListScans_RepoError(t *testing.T) {
	repoErr := errors.New("list query failed")

	scanRepo := newMockScanRepository()
	scanRepo.listFn = func(_ context.Context, _, _ int) ([]models.Scan, error) {
		return nil, repoErr
	}
	sbomRepo := &mockSbomRepository{}
	worker := &mockScanWorker{}

	svc := newTestScanService(scanRepo, sbomRepo, worker)

	_, err := svc.ListScans(context.Background(), 10, 0)
	if !errors.Is(err, ErrFailedToList) {
		t.Errorf("expected ErrFailedToList, got %v", err)
	}
	if !errors.Is(err, repoErr) {
		t.Errorf("expected repo error wrapped, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// CountScans tests
// ---------------------------------------------------------------------------

func TestCountScans_ReturnsTotal(t *testing.T) {
	scanRepo := newMockScanRepository()
	orgID := uuid.New()
	for i := 0; i < 4; i++ {
		id := uuid.New()
		scanRepo.scans[id] = &models.Scan{ID: id, OrgID: orgID}
	}

	sbomRepo := &mockSbomRepository{}
	worker := &mockScanWorker{}

	svc := newTestScanService(scanRepo, sbomRepo, worker)

	count, err := svc.CountScans(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 4 {
		t.Errorf("expected count 4, got %d", count)
	}
}
