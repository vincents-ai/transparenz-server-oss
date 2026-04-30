package middleware

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

const (
	lastUsedAtBatchSize = 100
	lastUsedAtInterval  = 5 * time.Second
	lastUsedAtBufSize   = 1024
)

// LastUsedAtUpdater batches last_used_at timestamp updates for webhook records.
type LastUsedAtUpdater struct {
	ch        chan uuid.UUID
	db        *gorm.DB
	logger    *zap.Logger
	tableName string
	stopCh    chan struct{}
}

// NewLastUsedAtUpdater creates a batched updater for last_used_at timestamps.
func NewLastUsedAtUpdater(db *gorm.DB, logger *zap.Logger, tableName string) *LastUsedAtUpdater {
	return &LastUsedAtUpdater{
		ch:        make(chan uuid.UUID, lastUsedAtBufSize),
		db:        db,
		logger:    logger,
		tableName: tableName,
		stopCh:    make(chan struct{}),
	}
}

func (u *LastUsedAtUpdater) Schedule(webhookID uuid.UUID) {
	select {
	case u.ch <- webhookID:
	default:
		u.logger.Warn("last_used_at updater channel full, dropping update",
			zap.String("table", u.tableName),
			zap.String("webhook_id", webhookID.String()),
		)
	}
}

func (u *LastUsedAtUpdater) Start(ctx context.Context) {
	ticker := time.NewTicker(lastUsedAtInterval)
	defer ticker.Stop()

	var batch []uuid.UUID

	flush := func() {
		if len(batch) == 0 {
			return
		}
		ids := make([]uuid.UUID, len(batch))
		copy(ids, batch)
		batch = batch[:0]

		if err := u.batchUpdate(ctx, ids); err != nil {
			u.logger.Error("failed to batch update last_used_at",
				zap.String("table", u.tableName),
				zap.Int("count", len(ids)),
				zap.Error(err),
			)
		}
	}

	for {
		select {
		case <-ctx.Done():
			for {
				select {
				case id := <-u.ch:
					batch = append(batch, id)
					if len(batch) >= lastUsedAtBatchSize {
						flush()
					}
				default:
					flush()
					return
				}
			}
		case <-u.stopCh:
			for {
				select {
				case id := <-u.ch:
					batch = append(batch, id)
					if len(batch) >= lastUsedAtBatchSize {
						flush()
					}
				default:
					flush()
					return
				}
			}
		case id := <-u.ch:
			batch = append(batch, id)
			if len(batch) >= lastUsedAtBatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (u *LastUsedAtUpdater) Stop() {
	select {
	case <-u.stopCh:
	default:
		close(u.stopCh)
	}
}

func (u *LastUsedAtUpdater) batchUpdate(ctx context.Context, ids []uuid.UUID) error {
	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids)+1)
	args[0] = time.Now().UTC()
	for i, id := range ids {
		placeholders[i] = fmt.Sprintf("$%d", i+2)
		args[i+1] = id
	}
	query := fmt.Sprintf(
		`UPDATE %s SET last_used_at = $1 WHERE id IN (%s)`,
		u.tableName,
		strings.Join(placeholders, ","),
	)
	return u.db.WithContext(ctx).Exec(query, args...).Error
}
