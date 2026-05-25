// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vincents-ai/vulnz/pkg/api"
	"github.com/vincents-ai/transparenz-server-oss/internal/testutil"
)

// ---------------------------------------------------------------------------
// fakeFeedSource — stub implementation of VulnzFeedSource for unit tests.
// ---------------------------------------------------------------------------

type fakeFeedSource struct {
	results []api.FetchResult
	err     error
	calls   int
}

func (f *fakeFeedSource) FetchEUFeeds(_ context.Context, _ []string) ([]api.FetchResult, error) {
	f.calls++
	return f.results, f.err
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

func TestVulnzSyncService_New(t *testing.T) {
	logger := testutil.TestLogger()
	src := &fakeFeedSource{}
	svc := NewVulnzSyncService(nil, src, 5*time.Minute, logger)
	if svc == nil {
		t.Fatal("expected non-nil VulnzSyncService")
	}
	if svc.syncInterval != 5*time.Minute {
		t.Errorf("expected syncInterval 5m, got %v", svc.syncInterval)
	}
	if svc.stopCh == nil {
		t.Error("expected stopCh to be initialised")
	}
}

// ---------------------------------------------------------------------------
// Stop — closes stopCh without panic
// ---------------------------------------------------------------------------

func TestVulnzSyncService_Stop_NoPanic(t *testing.T) {
	logger := testutil.TestLogger()
	src := &fakeFeedSource{}
	svc := NewVulnzSyncService(nil, src, time.Minute, logger)

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Stop() panicked: %v", r)
			}
		}()
		svc.Stop()
	}()
}

// TestVulnzSyncService_Start_ExitsOnStop verifies that Start returns promptly
// when Stop is called. We use a fake feed source that returns an error so
// SyncAll bails out immediately without hitting the network.
func TestVulnzSyncService_Start_ExitsOnStop(t *testing.T) {
	logger := testutil.TestLogger()
	src := &fakeFeedSource{err: errors.New("fake feed error")}
	svc := NewVulnzSyncService(nil, src, 24*time.Hour, logger) // interval so long ticker never fires

	ctx := context.Background()

	done := make(chan struct{})
	go func() {
		svc.Start(ctx)
		close(done)
	}()

	// Give Start enough time to finish the initial SyncAll (which errors
	// immediately), then signal stop.
	time.Sleep(50 * time.Millisecond)
	svc.Stop()

	select {
	case <-done:
		// Start exited — correct.
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not exit within 5s after Stop")
	}
}

// TestVulnzSyncService_Start_ExitsOnContextCancel verifies context-cancellation
// path directly (separate from Stop()).
func TestVulnzSyncService_Start_ExitsOnContextCancel(t *testing.T) {
	logger := testutil.TestLogger()
	src := &fakeFeedSource{err: errors.New("fake feed error")}
	svc := NewVulnzSyncService(nil, src, 24*time.Hour, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		svc.Start(ctx)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not exit within 5s after context timeout")
	}
}

// ---------------------------------------------------------------------------
// SyncAll — fake feed source with no records succeeds, calls FetchEUFeeds once
// ---------------------------------------------------------------------------

func TestVulnzSyncService_SyncAll_EmptyFeed_NoError(t *testing.T) {
	logger := testutil.TestLogger()
	src := &fakeFeedSource{
		results: []api.FetchResult{
			{Provider: "fake", Records: nil, Count: 0},
		},
	}
	svc := NewVulnzSyncService(nil, src, time.Minute, logger)

	err := svc.SyncAll(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if src.calls != 1 {
		t.Errorf("expected FetchEUFeeds called once, got %d", src.calls)
	}
}

// TestVulnzSyncService_SyncAll_FeedError propagates the error from the feed source.
func TestVulnzSyncService_SyncAll_FeedError(t *testing.T) {
	logger := testutil.TestLogger()
	want := errors.New("upstream feed unavailable")
	src := &fakeFeedSource{err: want}
	svc := NewVulnzSyncService(nil, src, time.Minute, logger)

	err := svc.SyncAll(context.Background())
	if !errors.Is(err, want) {
		t.Fatalf("expected wrapped %v, got %v", want, err)
	}
}

// TestVulnzSyncService_SyncAll_MultipleProviders verifies that all providers in
// the FetchResult slice are iterated.
func TestVulnzSyncService_SyncAll_MultipleProviders(t *testing.T) {
	logger := testutil.TestLogger()
	src := &fakeFeedSource{
		results: []api.FetchResult{
			{Provider: "euvd", Records: nil},
			{Provider: "kev", Records: nil},
			{Provider: "bsi-cert-bund", Records: nil},
		},
	}
	svc := NewVulnzSyncService(nil, src, time.Minute, logger)

	err := svc.SyncAll(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if src.calls != 1 {
		t.Errorf("expected FetchEUFeeds called once, got %d", src.calls)
	}
}

// ---------------------------------------------------------------------------
// upsertRecords — pure in-memory logic when feedRepo is nil / empty input
// ---------------------------------------------------------------------------

// TestVulnzSyncService_UpsertRecords_EmptyInput verifies that upsertRecords
// with an empty slice returns (0, 0) without touching any repository.
func TestVulnzSyncService_UpsertRecords_EmptyInput(t *testing.T) {
	logger := testutil.TestLogger()
	src := &fakeFeedSource{}
	svc := NewVulnzSyncService(nil, src, time.Minute, logger)

	synced, errs, cves := svc.upsertRecords(context.Background(), nil)
	if synced != 0 {
		t.Errorf("expected 0 synced, got %d", synced)
	}
	if errs != 0 {
		t.Errorf("expected 0 errors, got %d", errs)
	}
	if len(cves) != 0 {
		t.Errorf("expected 0 synced CVEs, got %d", len(cves))
	}
}

// ---------------------------------------------------------------------------
// Interface compliance check — compile-time only
// ---------------------------------------------------------------------------

var _ VulnzFeedSource = (*fakeFeedSource)(nil)
var _ VulnzFeedSource = NewRealVulnzFeedSource()
