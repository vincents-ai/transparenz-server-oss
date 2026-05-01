// Copyright (c) 2026 Vincent Palmer. All rights reserved.
package rest

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	"github.com/vincents-ai/transparenz-server-oss/pkg/middleware"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
	"github.com/vincents-ai/transparenz-server-oss/pkg/services"
	"github.com/vincents-ai/transparenz-server-oss/internal/testutil"
)

func setupAuditTestRouter(t *testing.T) (*gin.Engine, uuid.UUID) {
	t.Helper()
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "signing-key")

	db := testutil.SetupTestDB(t,
		"organizations", "scans", "vulnerabilities",
	)
	org := testutil.CreateTestOrg(t, db)
	requireNoErr := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("setup error: %v", err)
		}
	}
	sqlDB, err := db.DB()
	requireNoErr(err)
	_, err = sqlDB.Exec(`CREATE TABLE IF NOT EXISTS compliance.compliance_events (
		id TEXT PRIMARY KEY,
		org_id TEXT NOT NULL,
		event_type TEXT NOT NULL,
		severity TEXT NOT NULL,
		cve TEXT DEFAULT '',
		reported_to_authority TEXT DEFAULT '',
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		metadata TEXT DEFAULT '{}',
		signature TEXT DEFAULT '',
		signing_key_id TEXT,
		previous_event_hash TEXT DEFAULT '',
		event_hash TEXT DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	requireNoErr(err)
	_, err = sqlDB.Exec(`CREATE TABLE IF NOT EXISTS compliance.signing_keys (
		id TEXT PRIMARY KEY,
		org_id TEXT NOT NULL,
		public_key TEXT NOT NULL,
		key_algorithm TEXT NOT NULL DEFAULT 'ed25519',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		revoked_at DATETIME
	)`)
	requireNoErr(err)

	logger := zap.NewNop()
	signingSvc := services.NewSigningService(db, logger, keyPath)

	gin.SetMode(gin.TestMode)
	handler := NewAuditHandler(signingSvc)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("org_id", org.ID.String())
		c.Set("org_uuid", org.ID)
		c.Request = c.Request.WithContext(middleware.ContextWithOrgID(c.Request.Context(), org.ID))
		c.Next()
	})

	router.GET("/api/audit/verify", handler.VerifyAuditChain)

	return router, org.ID
}

func TestVerifyAuditChain_NoOrgContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewAuditHandler(nil)

	router := gin.New()
	router.GET("/api/audit/verify", handler.VerifyAuditChain)

	req := httptest.NewRequest(http.MethodGet, "/api/audit/verify?start=2024-01-01&end=2024-12-31", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestVerifyAuditChain_MissingStartParam(t *testing.T) {
	router, _ := setupAuditTestRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/api/audit/verify?end=2024-12-31", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestVerifyAuditChain_MissingEndParam(t *testing.T) {
	router, _ := setupAuditTestRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/api/audit/verify?start=2024-01-01", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestVerifyAuditChain_InvalidStartFormat(t *testing.T) {
	router, _ := setupAuditTestRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/api/audit/verify?start=01-01-2024&end=2024-12-31", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestVerifyAuditChain_InvalidEndFormat(t *testing.T) {
	router, _ := setupAuditTestRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/api/audit/verify?start=2024-01-01&end=not-a-date", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestVerifyAuditChain_EmptyResult(t *testing.T) {
	router, _ := setupAuditTestRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/api/audit/verify?start=2024-01-01&end=2024-12-31", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestVerifyAuditChain_WithSignedEvents(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "signing-key")

	db := testutil.SetupTestDB(t, "organizations", "scans", "vulnerabilities")
	org := testutil.CreateTestOrg(t, db)
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	_, err = sqlDB.Exec(`CREATE TABLE IF NOT EXISTS compliance.compliance_events (
		id TEXT PRIMARY KEY,
		org_id TEXT NOT NULL,
		event_type TEXT NOT NULL,
		severity TEXT NOT NULL,
		cve TEXT DEFAULT '',
		reported_to_authority TEXT DEFAULT '',
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		metadata TEXT DEFAULT '{}',
		signature TEXT DEFAULT '',
		signing_key_id TEXT,
		previous_event_hash TEXT DEFAULT '',
		event_hash TEXT DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		t.Fatalf("create events table: %v", err)
	}
	_, err = sqlDB.Exec(`CREATE TABLE IF NOT EXISTS compliance.signing_keys (
		id TEXT PRIMARY KEY,
		org_id TEXT NOT NULL,
		public_key TEXT NOT NULL,
		key_algorithm TEXT NOT NULL DEFAULT 'ed25519',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		revoked_at DATETIME
	)`)
	if err != nil {
		t.Fatalf("create signing_keys table: %v", err)
	}

	logger := zap.NewNop()
	signingSvc := services.NewSigningService(db, logger, keyPath)

	_, privKey, keyID, err := signingSvc.GenerateKeyPair(org.ID)
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	event1 := &models.ComplianceEvent{
		ID:        uuid.New(),
		OrgID:     org.ID,
		EventType: "vulnerability_discovered",
		Severity:  "high",
		Cve:       "CVE-2024-TEST",
		Metadata:  models.JSONMap{},
	}
	if err := signingSvc.SignEventWithKey(event1, privKey); err != nil {
		t.Fatalf("sign event1: %v", err)
	}
	event1.SigningKeyID = &keyID
	if err := db.Create(event1).Error; err != nil {
		t.Fatalf("insert event1: %v", err)
	}

	gin.SetMode(gin.TestMode)
	handler := NewAuditHandler(signingSvc)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("org_id", org.ID.String())
		c.Set("org_uuid", org.ID)
		c.Request = c.Request.WithContext(middleware.ContextWithOrgID(c.Request.Context(), org.ID))
		c.Next()
	})
	router.GET("/api/audit/verify", handler.VerifyAuditChain)

	req := httptest.NewRequest(http.MethodGet, "/api/audit/verify?start=2020-01-01&end=2030-12-31", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}
