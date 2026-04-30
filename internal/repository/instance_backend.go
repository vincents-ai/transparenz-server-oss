// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package repository

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type InstancePerOrgBackend struct {
	mu   sync.RWMutex
	pool map[uuid.UUID]*gorm.DB
	log  *zap.Logger
}

func NewInstancePerOrgBackend(log *zap.Logger) *InstancePerOrgBackend {
	return &InstancePerOrgBackend{
		pool: make(map[uuid.UUID]*gorm.DB),
		log:  log,
	}
}

func (b *InstancePerOrgBackend) Provision(ctx context.Context, orgID uuid.UUID, dsn string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, exists := b.pool[orgID]; exists {
		return fmt.Errorf("org %s already provisioned", orgID)
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("open instance connection for org %s: %w", orgID, err)
	}

	if err := db.Exec("SELECT 1").Error; err != nil {
		_ = closeDB(db)
		return fmt.Errorf("verify instance connection for org %s: %w", orgID, err)
	}

	b.pool[orgID] = db
	b.log.Info("provisioned instance backend",
		zap.String("org_id", orgID.String()),
	)
	return nil
}

func (b *InstancePerOrgBackend) Deprovision(ctx context.Context, orgID uuid.UUID) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	db, exists := b.pool[orgID]
	if !exists {
		return fmt.Errorf("org %s not provisioned", orgID)
	}

	if err := closeDB(db); err != nil {
		b.log.Warn("failed to close instance connection",
			zap.String("org_id", orgID.String()),
			zap.Error(err),
		)
	}

	delete(b.pool, orgID)
	b.log.Info("deprovisioned instance backend",
		zap.String("org_id", orgID.String()),
	)
	return nil
}

func (b *InstancePerOrgBackend) GetConnection(orgID uuid.UUID) (*gorm.DB, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	db, exists := b.pool[orgID]
	if !exists {
		return nil, fmt.Errorf("org %s not provisioned", orgID)
	}
	return db, nil
}

func (b *InstancePerOrgBackend) HealthCheck(ctx context.Context) map[uuid.UUID]error {
	b.mu.RLock()
	defer b.mu.RUnlock()

	results := make(map[uuid.UUID]error)
	for orgID, db := range b.pool {
		if err := db.Exec("SELECT 1").Error; err != nil {
			results[orgID] = err
		}
	}
	return results
}

func (b *InstancePerOrgBackend) SetOrgContext(ctx context.Context, orgID uuid.UUID) context.Context {
	return context.WithValue(ctx, orgKey(orgID), orgID.String())
}

func (b *InstancePerOrgBackend) GetDB() *gorm.DB {
	return nil
}

func (b *InstancePerOrgBackend) CreateOrgSchema(ctx context.Context, orgID uuid.UUID) error {
	return fmt.Errorf("instance_per_org backend: use Provision instead of CreateOrgSchema")
}

func (b *InstancePerOrgBackend) DropOrgSchema(ctx context.Context, orgID uuid.UUID) error {
	return b.Deprovision(ctx, orgID)
}

func closeDB(db *gorm.DB) error {
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}
