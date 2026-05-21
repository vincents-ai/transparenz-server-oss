// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	err = db.Exec("ATTACH DATABASE ':memory:' AS compliance").Error
	require.NoError(t, err)

	err = db.Exec(`
		CREATE TABLE IF NOT EXISTS "compliance"."jobs" (
			id TEXT PRIMARY KEY,
			type TEXT NOT NULL,
			payload TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending',
			max_retries INTEGER NOT NULL DEFAULT 3,
			retry_count INTEGER NOT NULL DEFAULT 0,
			scheduled_at DATETIME NOT NULL DEFAULT (datetime('now')),
			started_at DATETIME,
			completed_at DATETIME,
			error TEXT,
			created_at DATETIME NOT NULL DEFAULT (datetime('now')),
			updated_at DATETIME NOT NULL DEFAULT (datetime('now'))
		)
	`).Error
	require.NoError(t, err)

	return db
}

func testQueue(t *testing.T, db *gorm.DB) *JobQueue {
	t.Helper()
	return NewJobQueue(db, zap.NewNop(), 0)
}

func TestCalculateBackoff(t *testing.T) {
	tests := []struct {
		retryCount int
		expected   time.Duration
	}{
		{1, 2 * time.Minute},
		{2, 4 * time.Minute},
		{3, 8 * time.Minute},
		{5, 32 * time.Minute},
		{7, 60 * time.Minute},
		{10, 60 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("retry_%d", tt.retryCount), func(t *testing.T) {
			assert.Equal(t, tt.expected, calculateBackoff(tt.retryCount))
		})
	}
}

func TestEnqueue(t *testing.T) {
	db := setupTestDB(t)
	q := testQueue(t, db)
	ctx := context.Background()

	payload := map[string]string{"key": "value"}
	job, err := q.Enqueue(ctx, "test_type", payload)

	require.NoError(t, err)
	assert.NotEmpty(t, job.ID)
	assert.Equal(t, "test_type", job.Type)
	assert.Equal(t, "pending", job.Status)
	assert.Equal(t, 3, job.MaxRetries)
	assert.Equal(t, 0, job.RetryCount)
	assert.NotNil(t, job.Payload)
	assert.False(t, job.ScheduledAt.IsZero())
	assert.False(t, job.CreatedAt.IsZero())
}

func TestEnqueueDelayed(t *testing.T) {
	db := setupTestDB(t)
	q := testQueue(t, db)
	ctx := context.Background()

	future := time.Now().Add(1 * time.Hour)
	job, err := q.EnqueueDelayed(ctx, "test_type", map[string]string{"k": "v"}, future)

	require.NoError(t, err)
	assert.True(t, job.ScheduledAt.After(time.Now().Add(59*time.Minute)))
}

func TestEnqueuePreservesPayload(t *testing.T) {
	db := setupTestDB(t)
	q := testQueue(t, db)
	ctx := context.Background()

	type testPayload struct {
		ScanID string `json:"scan_id"`
		OrgID  string `json:"org_id"`
		Count  int    `json:"count"`
	}

	original := testPayload{ScanID: uuid.New().String(), OrgID: uuid.New().String(), Count: 42}
	job, err := q.Enqueue(ctx, "scan", original)
	require.NoError(t, err)

	var rawJob Job
	err = db.Where("id = ?", job.ID).First(&rawJob).Error
	require.NoError(t, err)

	var decoded testPayload
	err = json.Unmarshal(rawJob.Payload, &decoded)
	require.NoError(t, err)
	assert.Equal(t, original.ScanID, decoded.ScanID)
	assert.Equal(t, original.OrgID, decoded.OrgID)
	assert.Equal(t, original.Count, decoded.Count)
}

func TestComplete(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	job := &Job{
		ID:          uuid.New(),
		Type:        "scan",
		Payload:     json.RawMessage(`{}`),
		Status:      "running",
		MaxRetries:  3,
		ScheduledAt: time.Now(),
	}
	require.NoError(t, db.Create(job).Error)

	q := testQueue(t, db)
	err := q.Complete(ctx, job.ID)
	require.NoError(t, err)

	var updated Job
	db.Where("id = ?", job.ID).First(&updated)
	assert.Equal(t, "completed", updated.Status)
	assert.NotNil(t, updated.CompletedAt)
}

func TestCompleteOnNonRunningJob(t *testing.T) {
	db := setupTestDB(t)
	q := testQueue(t, db)
	ctx := context.Background()

	err := q.Complete(ctx, uuid.New())
	assert.Error(t, err)
}

func TestFailWithRetry(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	job := &Job{
		ID:          uuid.New(),
		Type:        "scan",
		Payload:     json.RawMessage(`{}`),
		Status:      "running",
		MaxRetries:  3,
		RetryCount:  0,
		ScheduledAt: time.Now(),
	}
	now := time.Now()
	job.StartedAt = &now
	require.NoError(t, db.Create(job).Error)

	q := testQueue(t, db)
	err := q.Fail(ctx, job.ID, errors.New("transient failure"))
	require.NoError(t, err)

	var updated Job
	db.Where("id = ?", job.ID).First(&updated)
	assert.Equal(t, "pending", updated.Status)
	assert.Equal(t, 1, updated.RetryCount)
	assert.Equal(t, "transient failure", updated.Error)
	assert.True(t, updated.ScheduledAt.After(time.Now().Add(-10*time.Second)))
	assert.Nil(t, updated.StartedAt)
}

func TestFailExhaustsRetries(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	job := &Job{
		ID:          uuid.New(),
		Type:        "scan",
		Payload:     json.RawMessage(`{}`),
		Status:      "running",
		MaxRetries:  3,
		RetryCount:  2,
		ScheduledAt: time.Now(),
	}
	now := time.Now()
	job.StartedAt = &now
	require.NoError(t, db.Create(job).Error)

	q := testQueue(t, db)
	err := q.Fail(ctx, job.ID, errors.New("persistent failure"))
	require.NoError(t, err)

	var final Job
	db.Where("id = ?", job.ID).First(&final)
	assert.Equal(t, "failed", final.Status)
	assert.Equal(t, 3, final.RetryCount)
	assert.NotNil(t, final.CompletedAt)
}

func TestFailOnCompletedJob(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	job := &Job{
		ID:          uuid.New(),
		Type:        "scan",
		Payload:     json.RawMessage(`{}`),
		Status:      "completed",
		MaxRetries:  3,
		ScheduledAt: time.Now(),
	}
	require.NoError(t, db.Create(job).Error)

	q := testQueue(t, db)
	err := q.Fail(ctx, job.ID, errors.New("should not work"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found or not running")
}

func TestFailOnNonExistentJob(t *testing.T) {
	db := setupTestDB(t)
	q := testQueue(t, db)
	ctx := context.Background()

	err := q.Fail(ctx, uuid.New(), errors.New("nope"))
	assert.Error(t, err)
}

func TestClaimReturnsNilWhenNoJobs(t *testing.T) {
	db := setupTestDB(t)
	q := testQueue(t, db)
	ctx := context.Background()

	claimed, err := q.Claim(ctx, "nonexistent_type")
	require.NoError(t, err)
	assert.Nil(t, claimed)
}

func TestClaimSkipsWrongType(t *testing.T) {
	db := setupTestDB(t)
	q := testQueue(t, db)
	ctx := context.Background()

	job := &Job{
		ID:          uuid.New(),
		Type:        "other_type",
		Payload:     json.RawMessage(`{}`),
		Status:      "pending",
		MaxRetries:  3,
		ScheduledAt: time.Now(),
	}
	require.NoError(t, db.Create(job).Error)

	claimed, err := q.Claim(ctx, "scan")
	require.NoError(t, err)
	assert.Nil(t, claimed)
}

func TestClaimSkipsScheduledFuture(t *testing.T) {
	db := setupTestDB(t)
	q := testQueue(t, db)
	ctx := context.Background()

	job := &Job{
		ID:          uuid.New(),
		Type:        "scan",
		Payload:     json.RawMessage(`{}`),
		Status:      "pending",
		MaxRetries:  3,
		ScheduledAt: time.Now().Add(1 * time.Hour),
	}
	require.NoError(t, db.Create(job).Error)

	claimed, err := q.Claim(ctx, "scan")
	require.NoError(t, err)
	assert.Nil(t, claimed)
}

func TestClaimClaimsAvailableJob(t *testing.T) {
	db := setupTestDB(t)
	q := testQueue(t, db)
	ctx := context.Background()

	job := &Job{
		ID:          uuid.New(),
		Type:        "scan",
		Payload:     json.RawMessage(`{"scan_id":"123"}`),
		Status:      "pending",
		MaxRetries:  3,
		ScheduledAt: time.Now(),
	}
	require.NoError(t, db.Create(job).Error)

	claimed, err := q.Claim(ctx, "scan")
	require.NoError(t, err)
	require.NotNil(t, claimed)
	assert.Equal(t, "running", claimed.Status)
	assert.NotNil(t, claimed.StartedAt)

	var updated Job
	db.Where("id = ?", claimed.ID).First(&updated)
	assert.Equal(t, "running", updated.Status)
}
