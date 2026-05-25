// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package services

import (
	"context"
	"testing"
	"time"

	"github.com/vincents-ai/transparenz-server-oss/internal/testutil"
)

func TestAlertHub_BroadcastToSubscriber(t *testing.T) {
	logger := testutil.TestLogger()
	hub := NewAlertHub(logger)

	ch, unsub := hub.Subscribe("org-1")
	defer unsub()

	alert := &Alert{
		Type:      "sla_warning",
		Severity:  "warning",
		Message:   "SLA approaching deadline",
		CVE:       "CVE-2024-1234",
		Timestamp: time.Now(),
	}

	hub.Broadcast("org-1", alert)

	select {
	case received := <-ch:
		if received.Type != "sla_warning" {
			t.Errorf("expected type sla_warning, got %s", received.Type)
		}
		if received.CVE != "CVE-2024-1234" {
			t.Errorf("expected CVE CVE-2024-1234, got %s", received.CVE)
		}
		if received.Severity != "warning" {
			t.Errorf("expected severity warning, got %s", received.Severity)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for alert")
	}
}

func TestAlertHub_NoBroadcastToDifferentOrg(t *testing.T) {
	logger := testutil.TestLogger()
	hub := NewAlertHub(logger)

	ch, unsub := hub.Subscribe("org-1")
	defer unsub()

	hub.Broadcast("org-2", &Alert{
		Type:      "sla_violation",
		Severity:  "critical",
		Message:   "SLA violated",
		CVE:       "CVE-2024-5678",
		Timestamp: time.Now(),
	})

	select {
	case <-ch:
		t.Fatal("should not receive alert from different org")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestAlertHub_Unsubscribe(t *testing.T) {
	logger := testutil.TestLogger()
	hub := NewAlertHub(logger)

	ch, unsub := hub.Subscribe("org-1")

	hub.Broadcast("org-1", &Alert{
		Type:      "test",
		Severity:  "info",
		Message:   "before unsub",
		Timestamp: time.Now(),
	})

	received := <-ch
	if received.Message != "before unsub" {
		t.Fatalf("expected 'before unsub', got %s", received.Message)
	}

	unsub()

	// After unsubscribe, the channel is removed from the hub but not closed.
	// Verify no more broadcasts arrive by sending another alert.
	hub.Broadcast("org-1", &Alert{
		Type:      "test",
		Severity:  "info",
		Message:   "after unsub",
		Timestamp: time.Now(),
	})

	select {
	case msg, ok := <-ch:
		if ok && msg.Message == "after unsub" {
			t.Fatal("should not receive broadcast after unsubscribe")
		}
	case <-time.After(100 * time.Millisecond):
		// Expected: no message received within timeout
	}
}

func TestAlertHub_MultipleSubscribers(t *testing.T) {
	logger := testutil.TestLogger()
	hub := NewAlertHub(logger)

	ch1, unsub1 := hub.Subscribe("org-1")
	defer unsub1()
	ch2, unsub2 := hub.Subscribe("org-1")
	defer unsub2()

	alert := &Alert{
		Type:      "exploited",
		Severity:  "critical",
		Message:   "KEV detected",
		CVE:       "CVE-2024-9999",
		Timestamp: time.Now(),
	}

	hub.Broadcast("org-1", alert)

	received1 := <-ch1
	received2 := <-ch2

	if received1.CVE != "CVE-2024-9999" {
		t.Errorf("subscriber 1: expected CVE CVE-2024-9999, got %s", received1.CVE)
	}
	if received2.CVE != "CVE-2024-9999" {
		t.Errorf("subscriber 2: expected CVE CVE-2024-9999, got %s", received2.CVE)
	}
}

func TestAlertHub_BroadcastToEmptyOrg(t *testing.T) {
	logger := testutil.TestLogger()
	hub := NewAlertHub(logger)

	hub.Broadcast("nonexistent-org", &Alert{
		Type:      "test",
		Severity:  "info",
		Message:   "no subscribers",
		Timestamp: time.Now(),
	})
}

func TestAlertService_NewAlertService(t *testing.T) {
	logger := testutil.TestLogger()
	hub := NewAlertHub(logger)

	svc := NewAlertService(
		hub,
		nil,
		nil,
		nil,
		nil,
		nil,
		logger,
		0,
	)

	if svc == nil {
		t.Fatal("expected non-nil service")
	}
	if svc.stopCh == nil {
		t.Fatal("expected stopCh to be initialized")
	}
}

func TestAlertService_Stop(t *testing.T) {
	logger := testutil.TestLogger()
	hub := NewAlertHub(logger)

	svc := NewAlertService(hub, nil, nil, nil, nil, nil, logger, 0)

	done := make(chan struct{})
	go func() {
		svc.Start(context.Background())
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)
	svc.Stop()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Stop should cause Start to return")
	}
}

func TestAlertService_StartStopsOnContextCancel(t *testing.T) {
	logger := testutil.TestLogger()
	hub := NewAlertHub(logger)

	svc := NewAlertService(hub, nil, nil, nil, nil, nil, logger, 0)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		svc.Start(ctx)
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("context cancel should cause Start to return")
	}
}

func TestAlertService_DoubleStopPanics(t *testing.T) {
	logger := testutil.TestLogger()
	hub := NewAlertHub(logger)

	svc := NewAlertService(hub, nil, nil, nil, nil, nil, logger, 0)

	svc.Stop()

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on double Stop")
		}
	}()
	svc.Stop()
}
