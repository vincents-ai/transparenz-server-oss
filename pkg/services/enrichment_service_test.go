// SPDX-FileCopyrightText: 2026 Vincent Palmer
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Transparenz, an open-source CRA compliance server.
// It is licensed under the GNU Affero General Public License v3.0; see LICENSE.
package services

import (
	"context"
	"os"
	"testing"

	"go.uber.org/zap"
)

func TestEnrichmentService_New(t *testing.T) {
	dir := t.TempDir()
	dbPath := dir + "/enrichment.db"
	svc, err := NewEnrichmentService(dbPath, zap.NewNop())
	if err != nil {
		t.Fatalf("NewEnrichmentService: %v", err)
	}
	defer svc.Close(context.Background())
	if svc.IsReady() {
		t.Fatal("expected IsReady=false before Initialize")
	}
}

func TestEnrichmentService_Initialize(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow Initialize test")
	}
	dir := t.TempDir()
	svc, err := NewEnrichmentService(dir+"/enrichment.db", zap.NewNop())
	if err != nil {
		t.Fatalf("NewEnrichmentService: %v", err)
	}
	defer svc.Close(context.Background())

	ctx := context.Background()
	if err := svc.Initialize(ctx); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if !svc.IsReady() {
		t.Fatal("expected IsReady=true after Initialize")
	}
}

func TestEnrichmentService_Initialize_Idempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow Initialize test")
	}
	dir := t.TempDir()
	svc, err := NewEnrichmentService(dir+"/enrichment.db", zap.NewNop())
	if err != nil {
		t.Fatalf("NewEnrichmentService: %v", err)
	}
	defer svc.Close(context.Background())

	ctx := context.Background()
	if err := svc.Initialize(ctx); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if err := svc.Initialize(ctx); err != nil {
		t.Fatalf("Initialize (2nd call): %v", err)
	}
}

func TestEnrichmentService_EnrichVulnerability_NotReady(t *testing.T) {
	dir := t.TempDir()
	svc, err := NewEnrichmentService(dir+"/enrichment.db", zap.NewNop())
	if err != nil {
		t.Fatalf("NewEnrichmentService: %v", err)
	}
	defer svc.Close(context.Background())

	mappings, err := svc.EnrichVulnerability(context.Background(), "CVE-2021-44228", map[string]interface{}{
		"id": "CVE-2021-44228",
	})
	if err != nil {
		t.Fatalf("EnrichVulnerability when not ready: %v", err)
	}
	if len(mappings) != 0 {
		t.Fatalf("expected 0 mappings when providers not loaded, got %d", len(mappings))
	}
}

func TestEnrichmentService_Close(t *testing.T) {
	dir := t.TempDir()
	dbPath := dir + "/enrichment.db"
	svc, err := NewEnrichmentService(dbPath, zap.NewNop())
	if err != nil {
		t.Fatalf("NewEnrichmentService: %v", err)
	}

	if err := svc.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	_, err = os.Stat(dbPath)
	if os.IsNotExist(err) {
		t.Log("DB file cleaned up after Close (SQLite WAL mode)")
	}
}
