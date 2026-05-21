package services

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func newTestTierService() *TierService {
	return NewTierService(nil, nil, zap.NewNop())
}

func TestCheckGreenboneWebhookLimit_UnknownTier(t *testing.T) {
	svc := newTestTierService()
	orgID := uuid.New()

	err := svc.CheckGreenboneWebhookLimit(context.Background(), orgID, "nonexistent_tier")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnknownTier))
	assert.Contains(t, err.Error(), "nonexistent_tier")
}

func TestCheckSbomWebhookLimit_UnknownTier(t *testing.T) {
	svc := newTestTierService()
	orgID := uuid.New()

	err := svc.CheckSbomWebhookLimit(context.Background(), orgID, "nonexistent_tier")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnknownTier))
	assert.Contains(t, err.Error(), "nonexistent_tier")
}
