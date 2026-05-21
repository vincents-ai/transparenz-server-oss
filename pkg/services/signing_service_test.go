// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package services

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
)

func setupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	err = db.Exec("ATTACH DATABASE ':memory:' AS compliance").Error
	if err != nil {
		t.Fatal(err)
	}
	// Manual DDL since AutoMigrate generates SQLite-incompatible syntax for schema-qualified tables
	err = db.Exec(`CREATE TABLE IF NOT EXISTS "compliance"."organizations" (
		id text PRIMARY KEY, name text NOT NULL, slug text NOT NULL,
		enisa_submission_mode text DEFAULT 'export', csaf_scope text DEFAULT 'per_sbom',
		pdf_template text DEFAULT 'generic', sla_tracking_mode text DEFAULT 'per_cve',
		tier text NOT NULL DEFAULT 'standard', sla_mode text NOT NULL DEFAULT 'alerts_only',
		multi_tenant_mode text DEFAULT 'shared', enisa_api_endpoint text,
		enisa_api_key_encrypted text, support_period_months integer DEFAULT 60,
		support_start_date datetime, support_end_date datetime,
		created_at datetime, updated_at datetime
	)`).Error
	if err != nil {
		t.Fatal(err)
	}
	err = db.Exec(`CREATE TABLE IF NOT EXISTS "compliance"."signing_keys" (
		id text PRIMARY KEY, org_id text NOT NULL, public_key text NOT NULL,
		key_algorithm text NOT NULL DEFAULT 'ed25519',
		created_at datetime, revoked_at datetime
	)`).Error
	if err != nil {
		t.Fatal(err)
	}
	err = db.Exec(`CREATE TABLE IF NOT EXISTS "compliance"."compliance_events" (
		id text PRIMARY KEY, org_id text NOT NULL, event_type text NOT NULL,
		severity text NOT NULL, cve text, reported_to_authority text,
		timestamp datetime, metadata text DEFAULT '{}',
		signature text, signing_key_id text, previous_event_hash text,
		event_hash text, created_at datetime
	)`).Error
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func createTestOrg(t *testing.T, db *gorm.DB) uuid.UUID {
	t.Helper()
	org := &models.Organization{
		ID:   uuid.New(),
		Name: "test-org",
		Slug: "test-org-" + uuid.New().String()[:8],
	}
	if err := db.Create(org).Error; err != nil {
		t.Fatal(err)
	}
	return org.ID
}

func TestSigningService_GenerateKeyPair(t *testing.T) {
	db := setupTestDB(t)
	logger := zap.NewNop()
	svc := NewSigningService(db, logger, t.TempDir()+"/signing-key")
	orgID := createTestOrg(t, db)

	_, privKey, _, err := svc.GenerateKeyPair(orgID)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	pubKey, _, keyID, err := svc.GenerateKeyPair(orgID)
	if err != nil {
		t.Fatalf("second GenerateKeyPair failed: %v", err)
	}

	if pubKey == "" {
		t.Error("expected non-empty public key")
	}
	if len(privKey) != ed25519.PrivateKeySize {
		t.Errorf("expected private key size %d, got %d", ed25519.PrivateKeySize, len(privKey))
	}
	if keyID == uuid.Nil {
		t.Error("expected non-nil key ID")
	}

	var stored models.SigningKey
	if err := db.First(&stored, "id = ?", keyID).Error; err != nil {
		t.Fatalf("failed to find stored key: %v", err)
	}
	if stored.PublicKey != pubKey {
		t.Error("stored public key mismatch")
	}
	if stored.KeyAlgorithm != "ed25519" {
		t.Errorf("expected algorithm ed25519, got %s", stored.KeyAlgorithm)
	}
}

func TestSigningService_GetActiveKey_NoKey(t *testing.T) {
	db := setupTestDB(t)
	logger := zap.NewNop()
	svc := NewSigningService(db, logger, t.TempDir()+"/signing-key")
	orgID := createTestOrg(t, db)

	_, err := svc.GetActiveKey(orgID)
	if err == nil {
		t.Error("expected error when no active key exists")
	}
}

func TestSigningService_SignEvent_Roundtrip(t *testing.T) {
	db := setupTestDB(t)
	logger := zap.NewNop()
	svc := NewSigningService(db, logger, t.TempDir()+"/signing-key")
	orgID := createTestOrg(t, db)

	_, privKey, _, err := svc.GenerateKeyPair(orgID)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	event := &models.ComplianceEvent{
		ID:                  uuid.New(),
		OrgID:               orgID,
		EventType:           "test_event",
		Severity:            "high",
		Cve:                 "CVE-2024-0001",
		ReportedToAuthority: "BSI",
		Timestamp:           time.Now().UTC(),
		Metadata:            models.JSONMap{"source": "test"},
		PreviousEventHash:   "",
	}

	if err := svc.SignEventWithKey(event, privKey); err != nil {
		t.Fatalf("SignEvent failed: %v", err)
	}

	if event.Signature == "" {
		t.Error("expected non-empty signature")
	}
	if event.EventHash == "" {
		t.Error("expected non-empty event hash")
	}

	event2 := &models.ComplianceEvent{
		ID:                uuid.New(),
		OrgID:             orgID,
		EventType:         "test_event_2",
		Severity:          "critical",
		Timestamp:         time.Now().UTC(),
		Metadata:          models.JSONMap{},
		PreviousEventHash: event.EventHash,
	}

	if err := svc.SignEventWithKey(event2, privKey); err != nil {
		t.Fatalf("SignEvent failed for event2: %v", err)
	}

	if event2.PreviousEventHash != event.EventHash {
		t.Error("previous event hash not linked correctly")
	}
}

func TestSigningService_VerifyEventChain_Valid(t *testing.T) {
	db := setupTestDB(t)
	logger := zap.NewNop()
	svc := NewSigningService(db, logger, t.TempDir()+"/signing-key")
	orgID := createTestOrg(t, db)

	_, privKey, _, err := svc.GenerateKeyPair(orgID)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	now := time.Now().UTC()
	events := []*models.ComplianceEvent{
		{ID: uuid.New(), OrgID: orgID, EventType: "e1", Severity: "low", Timestamp: now, Metadata: models.JSONMap{}, PreviousEventHash: ""},
		{ID: uuid.New(), OrgID: orgID, EventType: "e2", Severity: "high", Timestamp: now.Add(time.Minute), Metadata: models.JSONMap{}, PreviousEventHash: ""},
	}

	for i, ev := range events {
		if err := svc.SignEventWithKey(ev, privKey); err != nil {
			t.Fatalf("SignEvent failed for event %d: %v", i, err)
		}
		if i > 0 {
			ev.PreviousEventHash = events[i-1].EventHash
			if err := svc.SignEventWithKey(ev, privKey); err != nil {
				t.Fatalf("Re-sign event %d with chain: %v", i, err)
			}
		}
		if err := db.Create(ev).Error; err != nil {
			t.Fatalf("failed to persist event %d: %v", i, err)
		}
	}

	results, err := svc.VerifyEventChain(orgID, now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("VerifyEventChain failed: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	for _, r := range results {
		if !r.Verified {
			t.Errorf("expected event %s to be verified, reason: %s", r.EventID, r.Reason)
		}
	}
}

func TestSigningService_SignEventWithKey_NilKey(t *testing.T) {
	db := setupTestDB(t)
	logger := zap.NewNop()
	svc := NewSigningService(db, logger, t.TempDir()+"/signing-key")

	event := &models.ComplianceEvent{
		ID:        uuid.New(),
		EventType: "test_event",
		Severity:  "high",
		Timestamp: time.Now().UTC(),
		Metadata:  models.JSONMap{},
	}

	err := svc.SignEventWithKey(event, nil)
	if err == nil {
		t.Error("expected error when signing with nil key")
	}
	if event.Signature != "" {
		t.Error("expected empty signature when signing fails")
	}
	if event.EventHash != "" {
		t.Error("expected empty event hash when signing fails")
	}

	// Also test with zero-length key
	var zeroKey ed25519.PrivateKey
	err = svc.SignEventWithKey(event, zeroKey)
	if err == nil {
		t.Error("expected error when signing with zero-length key")
	}

	// Verify that a valid key still works
	svcValid := NewSigningService(db, logger, t.TempDir()+"/signing-key")
	err = svcValid.SignEvent(event)
	if err != nil {
		t.Errorf("expected SignEvent to succeed with valid key: %v", err)
	}
	if event.Signature == "" {
		t.Error("expected non-empty signature with valid key")
	}
}

func TestSigningService_VerifyEventChain_Broken(t *testing.T) {
	db := setupTestDB(t)
	logger := zap.NewNop()
	svc := NewSigningService(db, logger, t.TempDir()+"/signing-key")
	orgID := createTestOrg(t, db)

	_, privKey, _, err := svc.GenerateKeyPair(orgID)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	now := time.Now().UTC()
	e1 := &models.ComplianceEvent{
		ID: uuid.New(), OrgID: orgID, EventType: "e1", Severity: "low",
		Timestamp: now, Metadata: models.JSONMap{}, PreviousEventHash: "",
	}
	if err := svc.SignEventWithKey(e1, privKey); err != nil {
		t.Fatal(err)
	}
	if err := db.Create(e1).Error; err != nil {
		t.Fatal(err)
	}

	e2 := &models.ComplianceEvent{
		ID: uuid.New(), OrgID: orgID, EventType: "e2", Severity: "high",
		Timestamp: now.Add(time.Minute), Metadata: models.JSONMap{},
		PreviousEventHash: "deadbeef",
	}
	if err := svc.SignEventWithKey(e2, privKey); err != nil {
		t.Fatal(err)
	}
	if err := db.Create(e2).Error; err != nil {
		t.Fatal(err)
	}

	results, err := svc.VerifyEventChain(orgID, now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("VerifyEventChain failed: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if !results[0].Verified {
		t.Error("first event should be verified")
	}
	if results[1].Verified {
		t.Error("second event should not be verified (chain broken)")
	}
	if results[1].Reason != "chain broken: previous hash mismatch" {
		t.Errorf("unexpected reason: %s", results[1].Reason)
	}
}
