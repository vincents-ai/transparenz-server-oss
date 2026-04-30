// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type Job struct {
	ID          uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	Type        string          `gorm:"type:text;not null" json:"type"`
	Payload     json.RawMessage `gorm:"type:jsonb;not null" json:"payload"`
	Status      string          `gorm:"type:text;not null;default:'pending'" json:"status"`
	MaxRetries  int             `gorm:"not null;default:3" json:"max_retries"`
	RetryCount  int             `gorm:"not null;default:0" json:"retry_count"`
	ScheduledAt time.Time       `gorm:"type:timestamptz;not null;default:NOW()" json:"scheduled_at"`
	StartedAt   *time.Time      `gorm:"type:timestamptz" json:"started_at"`
	CompletedAt *time.Time      `gorm:"type:timestamptz" json:"completed_at"`
	Error       string          `gorm:"type:text" json:"error,omitempty"`
	CreatedAt   time.Time       `gorm:"type:timestamptz;not null;default:NOW()" json:"created_at"`
	UpdatedAt   time.Time       `gorm:"type:timestamptz;not null;default:NOW()" json:"updated_at"`
}

func (Job) TableName() string {
	return "compliance.jobs"
}

type JobQueue struct {
	db           *gorm.DB
	logger       *zap.Logger
	pollInterval time.Duration
}

func NewJobQueue(db *gorm.DB, logger *zap.Logger, pollInterval time.Duration) *JobQueue {
	if pollInterval == 0 {
		pollInterval = 5 * time.Second
	}
	return &JobQueue{db: db, logger: logger, pollInterval: pollInterval}
}

func (q *JobQueue) Enqueue(ctx context.Context, jobType string, payload any) (*Job, error) {
	return q.EnqueueDelayed(ctx, jobType, payload, time.Now())
}

func (q *JobQueue) EnqueueDelayed(ctx context.Context, jobType string, payload any, runAt time.Time) (*Job, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal job payload: %w", err)
	}

	job := &Job{
		ID:          uuid.New(),
		Type:        jobType,
		Payload:     data,
		Status:      "pending",
		MaxRetries:  3,
		ScheduledAt: runAt,
	}

	if err := q.db.WithContext(ctx).Create(job).Error; err != nil {
		return nil, fmt.Errorf("failed to enqueue job: %w", err)
	}

	q.logger.Debug("job enqueued",
		zap.String("job_id", job.ID.String()),
		zap.String("type", jobType),
		zap.Time("scheduled_at", runAt),
	)

	return job, nil
}

func (q *JobQueue) Claim(ctx context.Context, jobType string) (*Job, error) {
	var job Job

	tx := q.db.WithContext(ctx).Begin()
	if tx.Error != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", tx.Error)
	}

	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	err := tx.Clauses(clause.Locking{Strength: clause.LockingStrengthUpdate, Options: clause.LockingOptionsSkipLocked}).
		Where("type = ? AND status = ? AND scheduled_at <= ?", jobType, "pending", time.Now()).
		Order("scheduled_at ASC").
		First(&job).Error

	if err != nil {
		tx.Rollback()
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to claim job: %w", err)
	}

	now := time.Now()
	job.Status = "running"
	job.StartedAt = &now

	if err := tx.Save(&job).Error; err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("failed to update claimed job: %w", err)
	}

	if err := tx.Commit().Error; err != nil {
		return nil, fmt.Errorf("failed to commit job claim: %w", err)
	}

	q.logger.Debug("job claimed",
		zap.String("job_id", job.ID.String()),
		zap.String("type", jobType),
	)

	return &job, nil
}

func (q *JobQueue) Complete(ctx context.Context, jobID uuid.UUID) error {
	now := time.Now()
	result := q.db.WithContext(ctx).
		Model(&Job{}).
		Where("id = ? AND status = ?", jobID, "running").
		Updates(map[string]any{
			"status":       "completed",
			"completed_at": now,
			"updated_at":   now,
		})

	if result.Error != nil {
		return fmt.Errorf("failed to complete job: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("job %s not found or not running", jobID)
	}

	q.logger.Debug("job completed", zap.String("job_id", jobID.String()))
	return nil
}

func (q *JobQueue) Fail(ctx context.Context, jobID uuid.UUID, jobErr error) error {
	tx := q.db.WithContext(ctx).Begin()
	if tx.Error != nil {
		return fmt.Errorf("failed to begin transaction: %w", tx.Error)
	}

	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	var job Job
	if err := tx.Where("id = ? AND status = ?", jobID, "running").First(&job).Error; err != nil {
		tx.Rollback()
		if err == gorm.ErrRecordNotFound {
			return fmt.Errorf("job %s not found or not running", jobID)
		}
		return fmt.Errorf("failed to fetch job: %w", err)
	}

	now := time.Now()
	errMsg := jobErr.Error()
	job.RetryCount++

	if job.RetryCount >= job.MaxRetries {
		job.Status = "failed"
		job.Error = errMsg
		job.CompletedAt = &now
		job.UpdatedAt = now

		if err := tx.Save(&job).Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to mark job as failed: %w", err)
		}

		if err := tx.Commit().Error; err != nil {
			return fmt.Errorf("failed to commit job failure: %w", err)
		}

		q.logger.Warn("job exhausted retries",
			zap.String("job_id", jobID.String()),
			zap.String("type", job.Type),
			zap.Int("retry_count", job.RetryCount),
			zap.Error(jobErr),
		)
		return nil
	}

	backoff := calculateBackoff(job.RetryCount)
	job.Status = "pending"
	job.Error = errMsg
	job.ScheduledAt = now.Add(backoff)
	job.StartedAt = nil
	job.UpdatedAt = now

	if err := tx.Save(&job).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to reschedule job: %w", err)
	}

	if err := tx.Commit().Error; err != nil {
		return fmt.Errorf("failed to commit job reschedule: %w", err)
	}

	q.logger.Info("job rescheduled with backoff",
		zap.String("job_id", jobID.String()),
		zap.String("type", job.Type),
		zap.Int("retry_count", job.RetryCount),
		zap.Duration("backoff", backoff),
		zap.Error(jobErr),
	)

	return nil
}

func (q *JobQueue) StartWorker(ctx context.Context, jobType string, handler func(context.Context, *Job) error) {
	q.logger.Info("starting job worker",
		zap.String("type", jobType),
	)

	ticker := time.NewTicker(q.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			q.logger.Info("job worker stopped", zap.String("type", jobType))
			return
		case <-ticker.C:
			job, err := q.Claim(ctx, jobType)
			if err != nil {
				q.logger.Error("failed to claim job",
					zap.String("type", jobType),
					zap.Error(err),
				)
				continue
			}

			if job == nil {
				continue
			}

			if err := handler(ctx, job); err != nil {
				if failErr := q.Fail(ctx, job.ID, err); failErr != nil {
					q.logger.Error("failed to mark job as failed",
						zap.String("job_id", job.ID.String()),
						zap.Error(failErr),
					)
				}
				continue
			}

			if compErr := q.Complete(ctx, job.ID); compErr != nil {
				q.logger.Error("failed to mark job as completed",
					zap.String("job_id", job.ID.String()),
					zap.Error(compErr),
				)
			}
		}
	}
}

func calculateBackoff(retryCount int) time.Duration {
	minutes := 1 << retryCount
	if minutes > 60 {
		minutes = 60
	}
	return time.Duration(minutes) * time.Minute
}
