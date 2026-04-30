// Copyright (c) 2026 Vincent Palmer. Licensed under AGPL-3.0.
package testcontext

import (
	"context"
	"fmt"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/transparenz/transparenz-server-oss/internal/config"
	"github.com/transparenz/transparenz-server-oss/internal/models"
	"github.com/transparenz/transparenz-server-oss/internal/services"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type PostgresContainer struct {
	DSN string
}

type TestTokens struct {
	AdminToken             string
	ComplianceOfficerToken string
	UserToken              string
}

type TestContext struct {
	Container *PostgresContainer
	DB        *gorm.DB
	Router    *gin.Engine
	Config    *config.Config
	Logger    *zap.Logger
	OrgID     string
	Tokens    *TestTokens
	AlertHub  *services.AlertHub
}

var (
	sharedOnce sync.Once
	sharedCtx  *TestContext
	sharedErr  error
)

func GetSharedContext() (*TestContext, error) {
	sharedOnce.Do(func() {
		ctx := context.Background()

		container, err := StartContainer(ctx)
		if err != nil {
			sharedErr = fmt.Errorf("failed to start container: %w", err)
			return
		}

		db, err := InitDatabase(ctx, container.DSN)
		if err != nil {
			sharedErr = fmt.Errorf("failed to init database: %w", err)
			return
		}

		logger := zap.NewNop()

		router, alertHub, _, err := BuildApp(ctx, db, logger)
		if err != nil {
			sharedErr = fmt.Errorf("failed to build app: %w", err)
			return
		}

		org, err := SeedTestOrg(db)
		if err != nil {
			sharedErr = fmt.Errorf("failed to seed org: %w", err)
			return
		}

		tokens, err := GenerateTokens(org.ID.String())
		if err != nil {
			sharedErr = fmt.Errorf("failed to generate tokens: %w", err)
			return
		}

		sharedCtx = &TestContext{
			Container: container,
			DB:        db,
			Router:    router,
			Logger:    logger,
			OrgID:     org.ID.String(),
			Tokens:    tokens,
			AlertHub:  alertHub,
		}
	})
	return sharedCtx, sharedErr
}

func ResetTestData() error {
	if sharedCtx == nil || sharedCtx.DB == nil {
		return nil
	}
	db := sharedCtx.DB
	db.Exec(`DO $$ DECLARE r RECORD; BEGIN FOR r IN (SELECT tablename FROM pg_tables WHERE schemaname = 'compliance') LOOP EXECUTE 'TRUNCATE TABLE compliance.' || quote_ident(r.tablename) || ' CASCADE'; END LOOP; END $$`)

	orgID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	org := models.Organization{
		ID:                  orgID,
		Name:                "Test Corp",
		Slug:                "test-corp",
		Tier:                "enterprise",
		EnisaSubmissionMode: "export",
		CsafScope:           "per_sbom",
		PdfTemplate:         "generic",
		SlaTrackingMode:     "per_cve",
		SlaMode:             "fully_automatic",
	}
	if err := db.Create(&org).Error; err != nil {
		return fmt.Errorf("failed to re-seed test org: %w", err)
	}
	return nil
}

func SetOrgTier(db *gorm.DB, orgID string, tier string) error {
	return db.Model(&models.Organization{}).Where("id = ?", orgID).Update("tier", tier).Error
}
