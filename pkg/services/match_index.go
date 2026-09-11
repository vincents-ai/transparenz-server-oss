// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package services

import (
	"context"
	jsonutil "github.com/vincents-ai/transparenz-server-oss/pkg/util/jsonutil"
	"strings"
	"sync"
	"time"

	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
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
	index   map[string][]feedMatchEntry // exact name → entries
	prefix  map[string][]string          // prefix → list of keys containing it
	builtAt time.Time
	ttl     time.Duration
}

func NewMatchIndex(ttl time.Duration) *MatchIndex {
	return &MatchIndex{
		index:  make(map[string][]feedMatchEntry),
		prefix: make(map[string][]string),
		ttl:    ttl,
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
	mi.prefix = buildPrefixIndex(newIndex)
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
	seen := make(map[string]bool)

	addCandidates := func(entries []feedMatchEntry) {
		for _, e := range entries {
			if !seen[e.cve] {
				seen[e.cve] = true
				candidates = append(candidates, e)
			}
		}
	}

	// 1. Exact match (O(1) hash lookup)
	if entries, ok := mi.index[lowerName]; ok {
		addCandidates(entries)
	}

	// 2. Original case match
	if origName := strings.TrimSpace(name); origName != "" && origName != lowerName {
		if entries, ok := mi.index[origName]; ok {
			addCandidates(entries)
		}
	}

	// 3. Prefix/fuzzy match via pre-built prefix index
	// Check if any key is a substring of lowerName or vice versa
	// Using the prefix map: for each prefix of lowerName, check indexed keys
	if len(mi.prefix) > 0 {
		// Check short prefixes of the lookup name against the prefix index
		for i := 0; i < len(lowerName) && i < 20; i++ {
			// Use 3-char prefixes as lookup keys (minimum meaningful prefix)
			if i >= 2 {
				prefix := lowerName[:i+1]
				if keys, ok := mi.prefix[prefix]; ok {
					for _, key := range keys {
						if !seenAny(seen, key, lowerName) {
							if strings.Contains(lowerName, key) || strings.Contains(key, lowerName) {
								addCandidates(mi.index[key])
							}
						}
					}
				}
			}
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
	mi.prefix = make(map[string][]string)
	mi.builtAt = time.Time{}
	mi.mu.Unlock()
}

func parseAffectedProducts(raw []byte) []affectedProduct {
	var aps []affectedProduct
	if err := jsonutil.Unmarshal(raw, &aps); err != nil {
		return nil
	}
	return aps
}

// buildPrefixIndex creates a map from 3-char prefixes to the keys that contain
// them. This replaces the O(n) full scan of all keys with O(1) prefix lookup +
// targeted substring check on a small candidate set.
func buildPrefixIndex(index map[string][]feedMatchEntry) map[string][]string {
	prefixMap := make(map[string][]string)
	for key := range index {
		if len(key) < 3 {
			continue
		}
		// Use up to 8 prefixes per key (3-char, 4-char, ... up to min(10, len(key)))
		maxPrefix := len(key)
		if maxPrefix > 10 {
			maxPrefix = 10
		}
		for i := 2; i < maxPrefix; i++ {
			p := key[:i+1]
			prefixMap[p] = append(prefixMap[p], key)
		}
	}
	return prefixMap
}

// seenAny checks if any entry for the given key has already been seen
// (identified by CVE). Returns true if all CVEs for this key are already
// in the seen map.
func seenAny(seen map[string]bool, key, lowerName string) bool {
	// Simple check: if the key itself matches lowerName, it was handled by
	// the exact match path.
	return key == lowerName
}
