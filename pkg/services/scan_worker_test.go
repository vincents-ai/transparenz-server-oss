// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package services

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vincents-ai/transparenz-server-oss/pkg/jobs"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
	"github.com/vincents-ai/transparenz-server-oss/pkg/repository"
	"github.com/vincents-ai/transparenz-server-oss/internal/testutil"
	"go.uber.org/zap"
)

// ---------------------------------------------------------------------------
// Fakes implementing the worker* interfaces — no real database required
// ---------------------------------------------------------------------------

type fakeScanRepo struct {
	mu       sync.Mutex
	scans    map[uuid.UUID]*models.Scan
	updated  []*models.Scan
	statuses []string
}

func newFakeScanRepo() *fakeScanRepo {
	return &fakeScanRepo{scans: make(map[uuid.UUID]*models.Scan)}
}

func (f *fakeScanRepo) GetByID(_ context.Context, id uuid.UUID) (*models.Scan, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.scans[id]
	if !ok {
		return nil, errors.New("scan not found")
	}
	return s, nil
}

func (f *fakeScanRepo) UpdateStatus(_ context.Context, _ uuid.UUID, status string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statuses = append(f.statuses, status)
	return nil
}

func (f *fakeScanRepo) Update(_ context.Context, scan *models.Scan) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updated = append(f.updated, scan)
	return nil
}

type fakeVulnRepo struct {
	mu      sync.Mutex
	created []*models.Vulnerability
}

func (f *fakeVulnRepo) Create(_ context.Context, orgID uuid.UUID, vuln *models.Vulnerability) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	vuln.OrgID = orgID
	vuln.ID = uuid.New()
	f.created = append(f.created, vuln)
	return nil
}

type fakeFeedRepo struct {
	entries map[string]*models.VulnerabilityFeed
}

func (f *fakeFeedRepo) GetByCVE(_ context.Context, cve string) (*models.VulnerabilityFeed, error) {
	if f.entries == nil {
		return nil, errors.New("not found")
	}
	entry, ok := f.entries[cve]
	if !ok {
		return nil, errors.New("not found")
	}
	return entry, nil
}

type fakeSbomRepo struct {
	result *repository.SbomDocumentResult
	err    error
}

func (f *fakeSbomRepo) GetDocumentAndFormatFromPublic(_ context.Context, _ uuid.UUID) (*repository.SbomDocumentResult, error) {
	return f.result, f.err
}

type fakeScanVulnRepo struct {
	mu      sync.Mutex
	batches [][]models.ScanVulnerability
}

func (f *fakeScanVulnRepo) CreateBatch(_ context.Context, records []models.ScanVulnerability) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.batches = append(f.batches, records)
	return nil
}

type fakeGRCRepo struct {
	mu      sync.Mutex
	deleted []string
	batches [][]models.GRCMapping
}

func (f *fakeGRCRepo) DeleteByVulnerability(_ context.Context, _ uuid.UUID, vulnID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleted = append(f.deleted, vulnID)
	return nil
}

func (f *fakeGRCRepo) CreateBatch(_ context.Context, mappings []models.GRCMapping) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.batches = append(f.batches, mappings)
	return nil
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

func TestScanWorker_New(t *testing.T) {
	logger := testutil.TestLogger()
	w := NewScanWorker(nil, nil, nil, nil, nil, logger, nil, nil)
	if w == nil {
		t.Fatal("expected non-nil ScanWorker")
	}
	if w.logger == nil {
		t.Error("expected logger to be set")
	}
}

// ---------------------------------------------------------------------------
// Setter methods (concurrency-safety validated by the -race detector)
// ---------------------------------------------------------------------------

func TestScanWorker_SetVulnzMatcher(t *testing.T) {
	logger := testutil.TestLogger()
	w := NewScanWorker(nil, nil, nil, nil, nil, logger, nil, nil)

	vm := &VulnzMatcher{}
	w.SetVulnzMatcher(vm)

	w.mu.RLock()
	got := w.vulnzMatcher
	w.mu.RUnlock()

	if got != vm {
		t.Error("SetVulnzMatcher did not store the matcher")
	}
}

func TestScanWorker_SetEnrichmentService_Nil(t *testing.T) {
	logger := testutil.TestLogger()
	w := NewScanWorker(nil, nil, nil, nil, nil, logger, nil, nil)

	w.SetEnrichmentService(nil) // nil is valid — disables enrichment

	w.mu.RLock()
	got := w.enrichment
	w.mu.RUnlock()

	if got != nil {
		t.Error("expected enrichment to be nil after SetEnrichmentService(nil)")
	}
}

func TestScanWorker_SetGRCMappingRepository_Nil(t *testing.T) {
	logger := testutil.TestLogger()
	w := NewScanWorker(nil, nil, nil, nil, nil, logger, nil, nil)

	w.SetGRCMappingRepository(nil)

	w.mu.RLock()
	got := w.grcRepo
	w.mu.RUnlock()

	if got != nil {
		t.Error("expected grcRepo to be nil after SetGRCMappingRepository(nil)")
	}
}

// ---------------------------------------------------------------------------
// handleJob — rejects invalid JSON payload before touching any repository
// ---------------------------------------------------------------------------

func TestScanWorker_HandleJob_InvalidPayload_ReturnsError(t *testing.T) {
	logger := testutil.TestLogger()
	w := NewScanWorker(nil, nil, nil, nil, nil, logger, nil, nil)

	job := &jobs.Job{
		ID:      uuid.New(),
		Type:    "scan",
		Payload: json.RawMessage(`not-valid-json`),
	}

	err := w.ProcessJob(context.Background(), job)
	if err == nil {
		t.Fatal("expected error for invalid JSON payload, got nil")
	}
}

// ---------------------------------------------------------------------------
// buildVulnRecord — pure function, no external dependencies
// ---------------------------------------------------------------------------

func TestBuildVulnRecord_AllFields(t *testing.T) {
	score := 7.5
	match := VulnerabilityMatch{
		CVE:            "CVE-2025-1234",
		Severity:       "High",
		CVSSScore:      &score,
		PackageName:    "openssl",
		PackageVersion: "3.0.0",
		Source:         "nvd",
	}

	record := buildVulnRecord(match)

	if record["id"] != "CVE-2025-1234" {
		t.Errorf("id: got %v, want CVE-2025-1234", record["id"])
	}
	if record["severity"] != "High" {
		t.Errorf("severity: got %v, want High", record["severity"])
	}
	if v, ok := record["cvss_score"]; !ok || v != 7.5 {
		t.Errorf("cvss_score: got %v, want 7.5", v)
	}
	if record["affected_package"] != "openssl@3.0.0" {
		t.Errorf("affected_package: got %v, want openssl@3.0.0", record["affected_package"])
	}

	cve, ok := record["cve"].(map[string]interface{})
	if !ok {
		t.Fatal("expected 'cve' to be a map")
	}
	if cve["id"] != "CVE-2025-1234" {
		t.Errorf("cve.id: got %v, want CVE-2025-1234", cve["id"])
	}
}

func TestBuildVulnRecord_MinimalFields(t *testing.T) {
	match := VulnerabilityMatch{
		CVE: "CVE-2025-0001",
	}

	record := buildVulnRecord(match)

	if record["id"] != "CVE-2025-0001" {
		t.Errorf("id: got %v, want CVE-2025-0001", record["id"])
	}
	if _, hasScore := record["cvss_score"]; hasScore {
		t.Error("cvss_score should be absent when CVSSScore is nil")
	}
	if _, hasSev := record["severity"]; hasSev {
		t.Error("severity should be absent when Severity is empty")
	}
	if _, hasPkg := record["affected_package"]; hasPkg {
		t.Error("affected_package should be absent when PackageName is empty")
	}
}

func TestBuildVulnRecord_PackageOnlyName(t *testing.T) {
	match := VulnerabilityMatch{
		CVE:         "CVE-2025-9999",
		PackageName: "curl",
		// PackageVersion intentionally empty
	}

	record := buildVulnRecord(match)
	// affected_package is only set when PackageName != ""
	if pkg, ok := record["affected_package"]; ok {
		if pkg != "curl@" {
			t.Errorf("affected_package: got %v, want curl@", pkg)
		}
	}
}

// ---------------------------------------------------------------------------
// Start — exits promptly when context is already cancelled
// ---------------------------------------------------------------------------

func TestScanWorker_Start_ExitsOnContextCancel(t *testing.T) {
	devLogger, _ := zap.NewDevelopment()
	queue := jobs.NewJobQueue(nil, devLogger, 0) // nil DB is fine when ctx is pre-cancelled

	w := NewScanWorker(nil, nil, nil, nil, queue, testutil.TestLogger(), nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Start is called

	done := make(chan struct{})
	go func() {
		w.Start(ctx)
		close(done)
	}()

	select {
	case <-done:
		// Worker exited promptly — correct behaviour.
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not exit within 2s after context cancel")
	}
}

// ---------------------------------------------------------------------------
// EnqueueScan — rejects nil queue (panics) — verify worker initialisation docs
// ---------------------------------------------------------------------------

func TestScanWorker_NilQueue_Construction(t *testing.T) {
	// Constructing with a nil queue is valid; errors surface only on Enqueue.
	logger := testutil.TestLogger()
	w := NewScanWorker(nil, nil, nil, nil, nil, logger, nil, nil)
	if w.queue != nil {
		t.Error("expected nil queue to be stored as nil")
	}
}

// ---------------------------------------------------------------------------
// Interface-based tests using fakes — no real DB required
// ---------------------------------------------------------------------------

// TestScanWorker_AcceptsInterfaceFakes verifies that NewScanWorker accepts
// values satisfying the worker* interfaces (compile-time + runtime proof).
func TestScanWorker_AcceptsInterfaceFakes(t *testing.T) {
	logger := testutil.TestLogger()

	scanRepo := newFakeScanRepo()
	vulnRepo := &fakeVulnRepo{}
	feedRepo := &fakeFeedRepo{}
	sbomRepo := &fakeSbomRepo{}
	scanVulnRepo := &fakeScanVulnRepo{}

	w := NewScanWorker(scanRepo, vulnRepo, feedRepo, sbomRepo, nil, logger, nil, scanVulnRepo)
	if w == nil {
		t.Fatal("expected non-nil ScanWorker when constructed with fakes")
	}
}

// TestScanWorker_SetGRCMappingRepository_WithFake verifies SetGRCMappingRepository
// accepts a value implementing workerGRCMappingRepository.
func TestScanWorker_SetGRCMappingRepository_WithFake(t *testing.T) {
	logger := testutil.TestLogger()
	w := NewScanWorker(nil, nil, nil, nil, nil, logger, nil, nil)

	grcRepo := &fakeGRCRepo{}
	w.SetGRCMappingRepository(grcRepo)

	w.mu.RLock()
	got := w.grcRepo
	w.mu.RUnlock()

	if got != grcRepo {
		t.Error("SetGRCMappingRepository did not store the fake repo")
	}
}

// TestScanWorker_ProcessScan_SbomError verifies that a SBOM load failure
// causes processScan to propagate the error.
func TestScanWorker_ProcessScan_SbomError(t *testing.T) {
	logger := testutil.TestLogger()

	sbomRepo := &fakeSbomRepo{err: errors.New("sbom not found")}
	scan := &models.Scan{
		ID:     uuid.New(),
		OrgID:  uuid.New(),
		SbomID: uuid.New(),
	}

	w := NewScanWorker(nil, nil, nil, sbomRepo, nil, logger, nil, nil)
	err := w.processScan(context.Background(), scan)
	if err == nil {
		t.Fatal("expected error when SBOM load fails, got nil")
	}
}

// TestScanWorker_ProcessScan_NoMatcher_CompletesWithStatus verifies that when
// the vulnzMatcher is nil, processScan marks the scan as completed using the
// fake scanRepo — no real DB required.
func TestScanWorker_ProcessScan_NoMatcher_CompletesWithStatus(t *testing.T) {
	logger := testutil.TestLogger()
	orgID := uuid.New()

	scanRepo := newFakeScanRepo()
	sbomRepo := &fakeSbomRepo{
		result: &repository.SbomDocumentResult{
			Document: []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","components":[]}`),
			Format:   "cyclonedx",
		},
	}
	scan := &models.Scan{
		ID:     uuid.New(),
		OrgID:  orgID,
		SbomID: uuid.New(),
	}
	scanRepo.scans[scan.ID] = scan

	w := NewScanWorker(scanRepo, nil, nil, sbomRepo, nil, logger, nil, nil)
	// vulnzMatcher is nil by default — processScanWithVulnzMatcher will mark complete
	err := w.processScan(context.Background(), scan)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if scan.Status != "completed" {
		t.Errorf("expected scan status 'completed', got %q", scan.Status)
	}
	if len(scanRepo.updated) == 0 {
		t.Error("expected scanRepo.Update to have been called")
	}
}

// TestScanWorker_ProcessScanWithVulnzMatcher_CreatesVulnsViaFakes verifies the
// full scan processing path using fakes: when matcher is nil, scan is marked
// completed and scanRepo.Update is called — all without a real DB.
func TestScanWorker_ProcessScanWithVulnzMatcher_NoMatcherCompletesViaScanRepo(t *testing.T) {
	logger := testutil.TestLogger()
	orgID := uuid.New()

	scanRepo := newFakeScanRepo()
	scan := &models.Scan{
		ID:     uuid.New(),
		OrgID:  orgID,
		SbomID: uuid.New(),
		Status: "pending",
	}
	scanRepo.scans[scan.ID] = scan

	sbomDoc := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","components":[]}`)

	w := NewScanWorker(scanRepo, nil, nil, nil, nil, logger, nil, nil)
	// No matcher set — should complete scan immediately.

	err := w.processScanWithVulnzMatcher(context.Background(), scan, sbomDoc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Scan was marked completed via fake scanRepo.Update.
	if scan.Status != "completed" {
		t.Errorf("expected status 'completed', got %q", scan.Status)
	}
	if len(scanRepo.updated) == 0 {
		t.Error("expected scanRepo.Update to have been called")
	}
}

// TestScanWorker_HandleJob_ScanNotFound verifies that ProcessJob propagates
// a scan-not-found error from the scan repository.
func TestScanWorker_HandleJob_ScanNotFound(t *testing.T) {
	logger := testutil.TestLogger()

	scanRepo := newFakeScanRepo() // empty — scan ID will not be found

	w := NewScanWorker(scanRepo, nil, nil, nil, nil, logger, nil, nil)

	payload, _ := json.Marshal(scanJobPayload{
		ScanID: uuid.New(),
		OrgID:  uuid.New(),
		SbomID: uuid.New(),
	})
	job := &jobs.Job{
		ID:      uuid.New(),
		Type:    "scan",
		Payload: payload,
	}

	err := w.ProcessJob(context.Background(), job)
	if err == nil {
		t.Fatal("expected error when scan not found, got nil")
	}
}
