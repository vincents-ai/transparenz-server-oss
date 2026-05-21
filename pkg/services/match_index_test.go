package services

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
)

func makeFeed(cve, severity, apName, apVersion string) models.VulnerabilityFeed {
	aps, _ := json.Marshal([]affectedProduct{
		{Name: apName, Vendor: "acme", Version: apVersion},
	})
	return models.VulnerabilityFeed{
		ID:               uuid.New(),
		Cve:              cve,
		EnisaSeverity:    severity,
		AffectedProducts: aps,
	}
}

func TestBuildAndLookup(t *testing.T) {
	feeds := []models.VulnerabilityFeed{
		makeFeed("CVE-2024-0001", "High", "openssl", "1.1.1"),
		makeFeed("CVE-2024-0002", "Critical", "libcurl", "7.88.0"),
		makeFeed("CVE-2024-0003", "Medium", "openssl", "*"),
	}

	mi := NewMatchIndex(5 * time.Minute)
	if err := mi.Build(context.Background(), feeds); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	t.Run("exact name and version match", func(t *testing.T) {
		entries := mi.Lookup("openssl", "1.1.1")
		if len(entries) == 0 {
			t.Fatal("expected at least one entry for openssl 1.1.1")
		}
		found := false
		for _, e := range entries {
			if e.cve == "CVE-2024-0001" {
				found = true
				break
			}
		}
		if !found {
			t.Error("CVE-2024-0001 not found in results")
		}
	})

	t.Run("wildcard versions return name-only matches", func(t *testing.T) {
		entries := mi.Lookup("openssl", "99.99.99")
		if len(entries) != 1 {
			t.Fatalf("expected 1 wildcard entry for openssl, got %d", len(entries))
		}
		if entries[0].cve != "CVE-2024-0003" {
			t.Errorf("expected CVE-2024-0003, got %s", entries[0].cve)
		}
	})

	t.Run("case-insensitive lookup", func(t *testing.T) {
		entries := mi.Lookup("OpenSSL", "1.1.1")
		if len(entries) == 0 {
			t.Fatal("expected case-insensitive match for OpenSSL 1.1.1")
		}
	})

	t.Run("no match for unknown package", func(t *testing.T) {
		entries := mi.Lookup("nonexistent", "1.0.0")
		if len(entries) != 0 {
			t.Errorf("expected 0 entries for unknown package, got %d", len(entries))
		}
	})
}

func TestIsStale(t *testing.T) {
	feeds := []models.VulnerabilityFeed{
		makeFeed("CVE-2024-0001", "High", "testpkg", "1.0.0"),
	}

	t.Run("fresh index not stale", func(t *testing.T) {
		mi := NewMatchIndex(5 * time.Minute)
		if err := mi.Build(context.Background(), feeds); err != nil {
			t.Fatalf("Build failed: %v", err)
		}
		if mi.IsStale() {
			t.Error("freshly built index should not be stale")
		}
	})

	t.Run("expired TTL is stale", func(t *testing.T) {
		mi := NewMatchIndex(1 * time.Nanosecond)
		if err := mi.Build(context.Background(), feeds); err != nil {
			t.Fatalf("Build failed: %v", err)
		}
		time.Sleep(1 * time.Millisecond)
		if !mi.IsStale() {
			t.Error("index with expired TTL should be stale")
		}
	})
}
