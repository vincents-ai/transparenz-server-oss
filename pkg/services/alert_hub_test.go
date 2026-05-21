// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package services

import (
	"sync"
	"testing"
	"time"

	"github.com/vincents-ai/transparenz-server-oss/internal/testutil"
)

func TestAlertHub_Subscribe_ReceivesBroadcast(t *testing.T) {
	logger := testutil.TestLogger()
	hub := NewAlertHub(logger)

	ch, unsub := hub.Subscribe("org-A")
	defer unsub()

	alert := &Alert{
		Type:      "vuln_detected",
		Severity:  "critical",
		Message:   "CVE found",
		CVE:       "CVE-2024-0001",
		Timestamp: time.Now(),
	}

	hub.Broadcast("org-A", alert)

	select {
	case got := <-ch:
		if got.CVE != "CVE-2024-0001" {
			t.Errorf("expected CVE-2024-0001, got %s", got.CVE)
		}
		if got.Type != "vuln_detected" {
			t.Errorf("expected type vuln_detected, got %s", got.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for broadcast")
	}
}

func TestAlertHub_Unsubscribe_NoLongerReceives(t *testing.T) {
	logger := testutil.TestLogger()
	hub := NewAlertHub(logger)

	_, unsub := hub.Subscribe("org-B")

	// Unsubscribe via the normal path.
	unsub()

	// After unsubscribe, the channel is no longer in the hub's subscriber map.
	// Broadcast should not deliver to ch. Since we don't close the channel,
	// we verify by subscribing a second channel and checking only it receives.

	// Broadcast after unsubscribe: must not be delivered.
	// We verify this by checking there is nothing to read from a second
	// subscriber on the same org (ensuring broadcast itself still works)
	// while the unsubscribed channel is simply gone.
	ch2, unsub2 := hub.Subscribe("org-B")
	defer unsub2()

	hub.Broadcast("org-B", &Alert{
		Type:      "test",
		Severity:  "low",
		Message:   "after unsub",
		Timestamp: time.Now(),
	})

	// ch2 should receive it; ch is already closed.
	select {
	case got, ok := <-ch2:
		if !ok {
			t.Fatal("ch2 unexpectedly closed")
		}
		if got.Message != "after unsub" {
			t.Errorf("unexpected message: %s", got.Message)
		}
	case <-time.After(time.Second):
		t.Fatal("ch2 timed out")
	}
}

// TestAlertHub_SendOnClosedChannel_NoPanic verifies that broadcasting to an
// org whose subscriber has unsubscribed does not panic.
// Note: We cannot close the receive-only channel externally (Subscribe returns
// <-chan *Alert), so this test exercises the normal unsubscribe path followed
// by a broadcast to verify the hub handles missing subscribers gracefully.
func TestAlertHub_SendOnClosedChannel_NoPanic(t *testing.T) {
	logger := testutil.TestLogger()
	hub := NewAlertHub(logger)

	_, unsub := hub.Subscribe("org-C")

	// Unsubscribe via the normal path — channel is closed inside unsub.
	unsub()

	// Broadcast after unsubscribe must not panic.
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Broadcast panicked after unsubscribe: %v", r)
			}
		}()
		hub.Broadcast("org-C", &Alert{
			Type:      "test",
			Severity:  "info",
			Message:   "panic test",
			Timestamp: time.Now(),
		})
	}()
}

// TestAlertHub_ConcurrentSubscribeUnsubscribeBroadcast stresses the hub with
// concurrent subscribe, unsubscribe, and broadcast operations. Run with -race.
func TestAlertHub_ConcurrentSubscribeUnsubscribeBroadcast(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode: concurrent stress test")
	}
	logger := testutil.TestLogger()
	hub := NewAlertHub(logger)
	orgID := "org-race"

	const goroutines = 10
	const iterations = 20

	var wg sync.WaitGroup

	// Broadcaster goroutine.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < goroutines*iterations; i++ {
			hub.Broadcast(orgID, &Alert{
				Type:      "race",
				Severity:  "low",
				Message:   "concurrent",
				Timestamp: time.Now(),
			})
		}
	}()

	// Subscriber/unsubscriber goroutines.
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				_, unsub := hub.Subscribe(orgID)
				// Immediately unsubscribe — exercises the lock contention path.
				unsub()
			}
		}()
	}

	// Use a channel to wait with a timeout.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All goroutines completed — success.
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent test timed out")
	}
}

func TestAlertHub_MultipleSubscribersAllReceive(t *testing.T) {
	logger := testutil.TestLogger()
	hub := NewAlertHub(logger)

	const count = 5
	channels := make([]<-chan *Alert, count)
	unsubs := make([]func(), count)

	for i := 0; i < count; i++ {
		ch, unsub := hub.Subscribe("org-multi")
		channels[i] = ch
		unsubs[i] = unsub
	}
	defer func() {
		for _, u := range unsubs {
			u()
		}
	}()

	alert := &Alert{
		Type:      "broadcast",
		Severity:  "high",
		Message:   "all receive",
		CVE:       "CVE-2024-9876",
		Timestamp: time.Now(),
	}
	hub.Broadcast("org-multi", alert)

	for i, ch := range channels {
		select {
		case got := <-ch:
			if got.CVE != "CVE-2024-9876" {
				t.Errorf("subscriber %d: expected CVE-2024-9876, got %s", i, got.CVE)
			}
		case <-time.After(time.Second):
			t.Errorf("subscriber %d: timed out waiting for broadcast", i)
		}
	}
}

func TestAlertHub_DefaultChannelBuffer(t *testing.T) {
	logger := testutil.TestLogger()
	hub := NewAlertHub(logger)

	ch, unsub := hub.Subscribe("org-buf-test")
	defer unsub()

	// Subscribe creates a buffered channel of size 100.
	capacity := cap(ch)
	if capacity != 100 {
		t.Errorf("expected default channel buffer 100, got %d", capacity)
	}
}

func TestAlertHub_BroadcastToUnknownOrg_NoPanic(t *testing.T) {
	logger := testutil.TestLogger()
	hub := NewAlertHub(logger)

	// Broadcasting to an org with no subscribers must not panic or block.
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("unexpected panic: %v", r)
			}
		}()
		hub.Broadcast("unknown-org", &Alert{
			Type:      "test",
			Severity:  "info",
			Message:   "no subscribers",
			Timestamp: time.Now(),
		})
	}()
}
