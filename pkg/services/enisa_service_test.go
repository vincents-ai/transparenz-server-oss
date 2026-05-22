// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vincents-ai/transparenz-server-oss/pkg/middleware"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
	"github.com/vincents-ai/transparenz-server-oss/pkg/repository"
	"github.com/vincents-ai/transparenz-server-oss/internal/testutil"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// enisaTestFixture holds all the pieces needed to run ENISAService tests
// against an in-memory SQLite database — no Postgres connection required.
type enisaTestFixture struct {
	svc     *ENISAService
	orgRepo *repository.OrganizationRepository
	subRepo *repository.EnisaSubmissionRepository
	db      *gorm.DB
}

func newENISATestService(t *testing.T) *enisaTestFixture {
	t.Helper()
	db := testutil.SetupTestDB(t,
		"organizations",
		"vulnerabilities",
		"vulnerability_feeds",
		"enisa_submissions",
	)
	// sla_tracking is needed by the CSAF generator
	require.NoError(t, db.Exec(`CREATE TABLE IF NOT EXISTS "compliance"."sla_tracking" (
		id text PRIMARY KEY, org_id text NOT NULL, cve text NOT NULL,
		sbom_id text, deadline datetime NOT NULL, status text DEFAULT 'pending',
		created_at datetime DEFAULT CURRENT_TIMESTAMP, updated_at datetime DEFAULT CURRENT_TIMESTAMP
	)`).Error)

	orgRepo := repository.NewOrganizationRepository(db)
	subRepo := repository.NewEnisaSubmissionRepository(db)
	feedRepo := repository.NewVulnerabilityFeedRepository(db)
	vulnRepo := repository.NewVulnerabilityRepository(db)
	slaRepo := repository.NewSlaTrackingRepository(db)

	generator := NewCSAFGeneratorWithOrg(vulnRepo, feedRepo, slaRepo, orgRepo)
	cryptoKey := "test-crypto-key-must-be-32-bytes"
	cryptoService, err := NewCryptoService(cryptoKey)
	require.NoError(t, err)

		svc := NewENISAService(orgRepo, subRepo, nil, generator, cryptoService, nil, zap.NewNop(), 0, 0, 0)
	return &enisaTestFixture{svc: svc, orgRepo: orgRepo, subRepo: subRepo, db: db}
}

func TestENISAService_Submit_ExportMode(t *testing.T) {
	fix := newENISATestService(t)

	org := &models.Organization{
		ID:                  uuid.New(),
		Name:                "ENISA Test Org",
		Slug:                "enisa-test",
		EnisaSubmissionMode: "export",
		CsafScope:           "per_sbom",
		SlaTrackingMode:     "per_cve",
	}
	require.NoError(t, fix.orgRepo.Create(context.Background(), org))

	// Seed the vulnerability that CSAF generation will look up.
	vuln := &models.Vulnerability{
		ID:       uuid.New(),
		OrgID:    org.ID,
		Cve:      "CVE-2024-1234",
		Severity: "high",
	}
	require.NoError(t, fix.db.Create(vuln).Error)

	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)
	sub, err := fix.svc.Submit(ctx, org.ID, "CVE-2024-1234", nil)

	require.NoError(t, err)
	assert.NotNil(t, sub)
	assert.Equal(t, "pending", sub.Status)
	assert.Equal(t, org.ID, sub.OrgID)
}

func TestENISAService_Submit_APIMode_MockServer(t *testing.T) {
	// Set up a mock ENISA HTTP server
	mockServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"accepted"}`))
	}))
	defer mockServer.Close()

	fix := newENISATestService(t)
	fix.svc.httpClient = mockServer.Client()

	// Encrypt a fake API key
	encryptedKey, encErr := fix.svc.cryptoService.Encrypt("fake-api-key")
	require.NoError(t, encErr)

	org := &models.Organization{
		ID:                   uuid.New(),
		Name:                 "API Mode Org",
		Slug:                 "api-mode-org",
		EnisaSubmissionMode:  "api",
		EnisaAPIEndpoint:     mockServer.URL,
		EnisaAPIKeyEncrypted: encryptedKey,
		CsafScope:            "per_sbom",
		SlaTrackingMode:      "per_cve",
	}
	require.NoError(t, fix.orgRepo.Create(context.Background(), org))

	// Seed the vulnerability that CSAF generation will look up.
	vuln := &models.Vulnerability{
		ID:       uuid.New(),
		OrgID:    org.ID,
		Cve:      "CVE-2024-5678",
		Severity: "medium",
	}
	require.NoError(t, fix.db.Create(vuln).Error)

	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)
	// The private IP check will cause submitToENISAAPI to fail (status becomes "failed").
	sub, err := fix.svc.Submit(ctx, org.ID, "CVE-2024-5678", nil)

	require.NoError(t, err)
	assert.NotNil(t, sub)
	assert.Equal(t, "failed", sub.Status)
}

func TestENISAService_Submit_UnknownMode(t *testing.T) {
	fix := newENISATestService(t)

	org := &models.Organization{
		ID:                  uuid.New(),
		Name:                "Unknown Mode Org",
		Slug:                "unknown-mode-org",
		EnisaSubmissionMode: "unknown_mode",
		CsafScope:           "per_sbom",
		SlaTrackingMode:     "per_cve",
	}
	require.NoError(t, fix.orgRepo.Create(context.Background(), org))

	// Seed the vulnerability so CSAF generation succeeds before the mode check.
	vuln := &models.Vulnerability{
		ID:       uuid.New(),
		OrgID:    org.ID,
		Cve:      "CVE-2024-9999",
		Severity: "low",
	}
	require.NoError(t, fix.db.Create(vuln).Error)

	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)
	sub, err := fix.svc.Submit(ctx, org.ID, "CVE-2024-9999", nil)

	assert.Error(t, err)
	assert.Nil(t, sub)
	assert.Contains(t, err.Error(), "unknown submission mode")
}

func TestENISAService_StartRetryWorker_StopsOnContextCancel(t *testing.T) {
	fix := newENISATestService(t)
	fix.svc.retryInterval = 100 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		fix.svc.StartRetryWorker(ctx)
		close(done)
	}()

	select {
	case <-done:
		// Worker stopped cleanly
	case <-time.After(2 * time.Second):
		t.Fatal("retry worker did not stop within timeout after context cancel")
	}
}
