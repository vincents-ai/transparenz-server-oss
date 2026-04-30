// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package services

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/transparenz/transparenz-server-oss/pkg/models"
)

type feedMatchEntry struct {
	cve           string
	severity      string
	kevExploited  bool
	enisaEuvdID   string
	bsiAdvisoryID string
	bsiSeverity   string
	baseScore     *float64
	version       string
	feedSource    string
}

type MatchIndex struct {
	mu      sync.RWMutex
	index   map[string][]feedMatchEntry
	builtAt time.Time
	ttl     time.Duration
}

func NewMatchIndex(ttl time.Duration) *MatchIndex {
	return &MatchIndex{
		index: make(map[string][]feedMatchEntry),
		ttl:   ttl,
	}
}

func (mi *MatchIndex) Build(ctx context.Context, feeds []models.VulnerabilityFeed) error {
	newIndex := make(map[string][]feedMatchEntry, len(feeds))

	for _, feed := range feeds {
		aps := parseAffectedProducts(feed.AffectedProducts)
		severity := strings.ToLower(feed.EnisaSeverity)
		if severity == "" {
			severity = "unknown"
		}

		for _, ap := range aps {
			version := strings.ToLower(ap.Version)
			if version == "" {
				version = "*"
			}

			entry := feedMatchEntry{
				cve:           feed.Cve,
				severity:      severity,
				kevExploited:  feed.KevExploited,
				enisaEuvdID:   feed.EnisaEuvdID,
				bsiAdvisoryID: feed.BsiAdvisoryID,
				bsiSeverity:   feed.BsiSeverity,
				baseScore:     feed.BaseScore,
				version:       version,
			}

			switch {
			case feed.BsiAdvisoryID != "":
				entry.feedSource = "bsi"
			case feed.EnisaEuvdID != "":
				entry.feedSource = "euvd"
			case feed.KevExploited:
				entry.feedSource = "kev"
			default:
				entry.feedSource = "unknown"
			}

			lowerName := strings.ToLower(ap.Name)
			if lowerName == "" {
				continue
			}

			newIndex[lowerName] = append(newIndex[lowerName], entry)

			origName := strings.TrimSpace(ap.Name)
			if origName != "" && origName != lowerName {
				newIndex[origName] = append(newIndex[origName], entry)
			}
		}
	}

	mi.mu.Lock()
	mi.index = newIndex
	mi.builtAt = time.Now()
	mi.mu.Unlock()

	return nil
}

func (mi *MatchIndex) Lookup(name, version string) []feedMatchEntry {
	mi.mu.RLock()
	defer mi.mu.RUnlock()

	if len(mi.index) == 0 {
		return nil
	}

	lowerName := strings.ToLower(name)
	lowerVersion := strings.ToLower(version)

	var candidates []feedMatchEntry

	if entries, ok := mi.index[lowerName]; ok {
		candidates = append(candidates, entries...)
	}

	if origName := strings.TrimSpace(name); origName != "" && origName != lowerName {
		if entries, ok := mi.index[origName]; ok {
			candidates = append(candidates, entries...)
		}
	}

	for key, entries := range mi.index {
		if key == lowerName || key == name {
			continue
		}
		if len(key) > len(lowerName)*3 {
			continue
		}
		shortLen := len(lowerName)
		longLen := len(key)
		if len(key) < len(lowerName) {
			shortLen = len(key)
			longLen = len(lowerName)
		}
		if longLen > 0 && float64(shortLen)/float64(longLen) < 0.5 {
			continue
		}
		if strings.Contains(lowerName, key) || strings.Contains(key, lowerName) {
			candidates = append(candidates, entries...)
		}
	}

	var results []feedMatchEntry
	vm := NewVersionMatcher()
	for _, entry := range candidates {
		if entry.version == "*" {
			results = append(results, entry)
		} else {
			result := vm.MatchVersion(lowerVersion, entry.version)
			if result == ExactMatch || result == RangeMatch {
				results = append(results, entry)
			}
		}
	}

	return results
}

func (mi *MatchIndex) IsStale() bool {
	mi.mu.RLock()
	defer mi.mu.RUnlock()

	if len(mi.index) == 0 {
		return true
	}

	return time.Since(mi.builtAt) > mi.ttl
}

func (mi *MatchIndex) Reset() {
	mi.mu.Lock()
	mi.index = make(map[string][]feedMatchEntry)
	mi.builtAt = time.Time{}
	mi.mu.Unlock()
}

func parseAffectedProducts(raw []byte) []affectedProduct {
	var aps []affectedProduct
	if err := json.Unmarshal(raw, &aps); err != nil {
		return nil
	}
	return aps
}
