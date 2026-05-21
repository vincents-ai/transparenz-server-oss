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
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// ---------------------------------------------------------------------------
// Mock telemetry repository
// ---------------------------------------------------------------------------

type mockTelemetryRepository struct {
	configs         map[uuid.UUID]*models.OrgTelemetryConfig
	getByOrgFn     func(ctx context.Context, orgID uuid.UUID) (*models.OrgTelemetryConfig, error)
	getAllFn       func(ctx context.Context) ([]*models.OrgTelemetryConfig, error)
	getByPrefixFn  func(ctx context.Context, prefix string) ([]*models.OrgTelemetryConfig, error)
	updateFn       func(ctx context.Context, config *models.OrgTelemetryConfig) error
}

func newMockTelemetryRepository() *mockTelemetryRepository {
	return &mockTelemetryRepository{
		configs: make(map[uuid.UUID]*models.OrgTelemetryConfig),
	}
}

func (m *mockTelemetryRepository) GetByOrgID(_ context.Context, orgID uuid.UUID) (*models.OrgTelemetryConfig, error) {
	if m.getByOrgFn != nil {
		return m.getByOrgFn(context.Background(), orgID)
	}
	c, ok := m.configs[orgID]
	if !ok {
		return nil, repository.ErrTelemetryConfigNotFound
	}
	return c, nil
}

func (m *mockTelemetryRepository) GetAllActive(_ context.Context) ([]*models.OrgTelemetryConfig, error) {
	if m.getAllFn != nil {
		return m.getAllFn(context.Background())
	}
	var result []*models.OrgTelemetryConfig
	for _, c := range m.configs {
		if c.Active {
			result = append(result, c)
		}
	}
	return result, nil
}

func (m *mockTelemetryRepository) Update(_ context.Context, config *models.OrgTelemetryConfig) error {
	if m.updateFn != nil {
		return m.updateFn(context.Background(), config)
	}
	m.configs[config.OrgID] = config
	return nil
}

func (m *mockTelemetryRepository) Create(_ context.Context, _ uuid.UUID, config *models.OrgTelemetryConfig) error {
	m.configs[config.OrgID] = config
	return nil
}

func (m *mockTelemetryRepository) GetByMetricsTokenPrefix(_ context.Context, prefix string) ([]*models.OrgTelemetryConfig, error) {
	if m.getByPrefixFn != nil {
		return m.getByPrefixFn(context.Background(), prefix)
	}
	var result []*models.OrgTelemetryConfig
	for _, c := range m.configs {
		if c.MetricsTokenPrefix == prefix {
			result = append(result, c)
		}
	}
	if len(result) == 0 {
		return nil, repository.ErrTelemetryConfigNotFound
	}
	return result, nil
}

// newTestTelemetryService creates a TelemetryService backed by a mock repo.
func newTestTelemetryService(repo *mockTelemetryRepository) *TelemetryService {
	return &TelemetryService{
		telemetryRepo: repo,
		hub:           NewAlertHub(zap.NewNop()),
		logger:        zap.NewNop(),
		breakers:      make(map[string]*circuitBreakerState),
	}
}

// ---------------------------------------------------------------------------
// HashMetricsToken tests
// ---------------------------------------------------------------------------

func TestHashMetricsToken_NonEmpty(t *testing.T) {
	hash, _, err := HashMetricsToken("my-secret-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hash == "" {
		t.Error("expected non-empty hash")
	}
}

func TestHashMetricsToken_BcryptVerifies(t *testing.T) {
	token := "test-token-abc123"
	hash, _, err := HashMetricsToken(token)
	if err != nil {
		t.Fatalf("unexpected error hashing: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(token)); err != nil {
		t.Errorf("bcrypt verification failed for original token: %v", err)
	}
}

func TestHashMetricsToken_DifferentCallsDifferentHashes(t *testing.T) {
	token := "same-token"
	hash1, _, err := HashMetricsToken(token)
	if err != nil {
		t.Fatalf("first hash error: %v", err)
	}
	hash2, _, err := HashMetricsToken(token)
	if err != nil {
		t.Fatalf("second hash error: %v", err)
	}
	// bcrypt salts guarantee different outputs for the same input
	if hash1 == hash2 {
		t.Error("expected different hashes for same token (bcrypt salting)")
	}
}

// ---------------------------------------------------------------------------
// RotateToken tests
// ---------------------------------------------------------------------------

func TestRotateToken_ReturnsNonEmptyToken(t *testing.T) {
	orgID := uuid.New()
	repo := newMockTelemetryRepository()
	repo.configs[orgID] = &models.OrgTelemetryConfig{
		OrgID:            orgID,
		Active:           true,
		MetricsTokenHash: "old-hash",
	}

	svc := newTestTelemetryService(repo)

	token, err := svc.RotateToken(context.Background(), orgID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token == "" {
		t.Error("expected non-empty token after rotation")
	}
}

func TestRotateToken_DifferentCallsDifferentTokens(t *testing.T) {
	orgID := uuid.New()
	repo := newMockTelemetryRepository()
	repo.configs[orgID] = &models.OrgTelemetryConfig{
		OrgID:            orgID,
		Active:           true,
		MetricsTokenHash: "old-hash",
	}

	svc := newTestTelemetryService(repo)

	token1, err := svc.RotateToken(context.Background(), orgID)
	if err != nil {
		t.Fatalf("first rotate error: %v", err)
	}

	// Reset hash so second call works
	repo.configs[orgID].MetricsTokenHash = "updated-hash"

	token2, err := svc.RotateToken(context.Background(), orgID)
	if err != nil {
		t.Fatalf("second rotate error: %v", err)
	}
	if token1 == token2 {
		t.Error("expected different tokens on successive rotations")
	}
}

func TestRotateToken_OrgNotFound(t *testing.T) {
	repo := newMockTelemetryRepository()
	svc := newTestTelemetryService(repo)

	_, err := svc.RotateToken(context.Background(), uuid.New())
	if !errors.Is(err, repository.ErrTelemetryConfigNotFound) {
		t.Errorf("expected ErrTelemetryConfigNotFound, got %v", err)
	}
}

func TestRotateToken_UpdateError(t *testing.T) {
	orgID := uuid.New()
	updateErr := errors.New("update failed")

	repo := newMockTelemetryRepository()
	repo.configs[orgID] = &models.OrgTelemetryConfig{
		OrgID:            orgID,
		Active:           true,
		MetricsTokenHash: "old-hash",
	}
	repo.updateFn = func(_ context.Context, _ *models.OrgTelemetryConfig) error {
		return updateErr
	}

	svc := newTestTelemetryService(repo)

	_, err := svc.RotateToken(context.Background(), orgID)
	if !errors.Is(err, updateErr) {
		t.Errorf("expected update error to be propagated, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// GetMetricsForOrg tests
// ---------------------------------------------------------------------------

func TestGetMetricsForOrg_ValidToken(t *testing.T) {
	orgID := uuid.New()
	token := "valid-metrics-token"
	hash, prefix, err := HashMetricsToken(token)
	if err != nil {
		t.Fatalf("hash token: %v", err)
	}

	repo := newMockTelemetryRepository()
	repo.configs[orgID] = &models.OrgTelemetryConfig{
		OrgID:              orgID,
		Active:             true,
		MetricsTokenHash:   hash,
		MetricsTokenPrefix: prefix,
	}

	svc := newTestTelemetryService(repo)

	// Result may be empty string (no counters incremented), but no error expected.
	_, err = svc.GetMetricsForOrg(context.Background(), token)
	if err != nil {
		t.Fatalf("unexpected error for valid token: %v", err)
	}
}

func TestGetMetricsForOrg_WrongToken(t *testing.T) {
	orgID := uuid.New()
	hash, prefix, err := HashMetricsToken("correct-token")
	if err != nil {
		t.Fatalf("hash token: %v", err)
	}

	repo := newMockTelemetryRepository()
	repo.configs[orgID] = &models.OrgTelemetryConfig{
		OrgID:              orgID,
		Active:             true,
		MetricsTokenHash:   hash,
		MetricsTokenPrefix: prefix,
	}

	svc := newTestTelemetryService(repo)

	_, err = svc.GetMetricsForOrg(context.Background(), "wrong-token")
	if !errors.Is(err, repository.ErrTelemetryConfigNotFound) {
		t.Errorf("expected ErrTelemetryConfigNotFound for wrong token, got %v", err)
	}
}

func TestGetMetricsForOrg_NoConfigs(t *testing.T) {
	repo := newMockTelemetryRepository()
	repo.getAllFn = func(_ context.Context) ([]*models.OrgTelemetryConfig, error) {
		return nil, nil
	}

	svc := newTestTelemetryService(repo)

	_, err := svc.GetMetricsForOrg(context.Background(), "any-token")
	if !errors.Is(err, repository.ErrTelemetryConfigNotFound) {
		t.Errorf("expected ErrTelemetryConfigNotFound for empty config list, got %v", err)
	}
}

func TestGetMetricsForOrg_RepoError(t *testing.T) {
	repoErr := errors.New("db unavailable")

	repo := newMockTelemetryRepository()
	repo.getByPrefixFn = func(_ context.Context, _ string) ([]*models.OrgTelemetryConfig, error) {
		return nil, repoErr
	}

	svc := newTestTelemetryService(repo)

	_, err := svc.GetMetricsForOrg(context.Background(), "any-token")
	if !errors.Is(err, repoErr) {
		t.Errorf("expected repo error propagated, got %v", err)
	}
}
