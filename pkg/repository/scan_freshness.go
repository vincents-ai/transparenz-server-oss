// SPDX-FileCopyrightText: 2026 Vincent Palmer
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Transparenz, an open-source CRA compliance server.
// It is licensed under the GNU Affero General Public License v3.0; see LICENSE.

package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
)

// SbomFreshness reports whether an SBOM has been checked against the vulnerability
// data the server currently holds.
//
// It exists because of a specific way a compliance dashboard lies. In this edition
// scanning is triggered by an operator rather than automatically after a feed
// update, so an SBOM can sit unexamined while the feed gains a CVE that affects it.
// A green "no outstanding obligations" status says nothing about that: the finding
// was never generated, so no deadline was ever computed from it. Staleness has to
// be visible next to the status, or the status means less than it appears to.
type SbomFreshness struct {
	SbomID         uuid.UUID  `json:"sbom_id"`
	Filename       string     `json:"filename"`
	LastScannedAt  *time.Time `json:"last_scanned_at,omitempty"`
	LastScanStatus string     `json:"last_scan_status,omitempty"`
	// ScannedAfterFeedSync is true only when a scan completed at or after the
	// newest feed sync, so the SBOM has been examined against the data in hand.
	ScannedAfterFeedSync bool `json:"scanned_after_feed_sync"`
	// Stale is true when the SBOM has never been scanned, or when the newest feed
	// sync is later than its newest scan: there may be matches nobody looked for.
	Stale bool `json:"stale"`
}

// ScanFreshness is the organisation-wide view, including the feed's own age.
type ScanFreshness struct {
	FeedLastSyncedAt *time.Time      `json:"feed_last_synced_at,omitempty"`
	Sboms            []SbomFreshness `json:"sboms"`
	Total            int             `json:"total"`
	Stale            int             `json:"stale"`
	// Note travels with the data, so a caller cannot read the counts without the
	// caveat that produced them.
	Note string `json:"note"`
}

const scanFreshnessNote = "Scanning in this edition is operator-triggered, so an SBOM marked fresh " +
	"was scanned at or after the feed's latest sync — it does not mean it will stay current. " +
	"An SBOM marked stale may contain vulnerability matches nobody has looked for, and no " +
	"regulatory deadline is computed for a finding that was never generated."

// Freshness returns per-SBOM scan age relative to the newest feed sync.
func (r *SbomRepository) Freshness(ctx context.Context) (*ScanFreshness, error) {
	out := &ScanFreshness{Note: scanFreshnessNote}

	// The newest feed sync, read as an ordered row rather than as MAX().
	//
	// MAX(last_synced_at) returns a driver-specific value — a time under PostgreSQL,
	// a string under SQLite — so scanning it into a time type works on one and fails
	// on the other. Ordering the model lets GORM convert the column the same way it
	// does everywhere else.
	var latestFeed []models.VulnerabilityFeed
	if err := r.db.WithContext(ctx).
		Model(&models.VulnerabilityFeed{}).
		Select("last_synced_at").
		Order("last_synced_at DESC").
		Limit(1).
		Find(&latestFeed).Error; err != nil {
		return nil, err
	}
	if len(latestFeed) > 0 && !latestFeed[0].LastSyncedAt.IsZero() {
		t := latestFeed[0].LastSyncedAt
		out.FeedLastSyncedAt = &t
	}

	var uploads []models.SbomUpload
	if err := r.db.WithContext(ctx).
		Scopes(TenantScope(ctx)).
		Select("id", "org_id", "filename").
		Order("created_at DESC").
		Find(&uploads).Error; err != nil {
		return nil, err
	}

	out.Sboms = make([]SbomFreshness, 0, len(uploads))
	for _, u := range uploads {
		row := SbomFreshness{SbomID: u.ID, Filename: u.Filename}

		var scans []models.Scan
		err := r.db.WithContext(ctx).
			Select("status", "scan_date").
			Where("org_id = ? AND sbom_id = ?", u.OrgID, u.ID).
			Order("scan_date DESC").
			Limit(1).
			Find(&scans).Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}

		if len(scans) > 0 && !scans[0].ScanDate.IsZero() {
			scanned := scans[0].ScanDate
			row.LastScannedAt = &scanned
			row.LastScanStatus = scans[0].Status
			row.ScannedAfterFeedSync = out.FeedLastSyncedAt == nil || !scanned.Before(*out.FeedLastSyncedAt)
		}

		// Never scanned counts as stale: nothing has been looked for at all.
		row.Stale = row.LastScannedAt == nil || !row.ScannedAfterFeedSync

		out.Sboms = append(out.Sboms, row)
		if row.Stale {
			out.Stale++
		}
	}
	out.Total = len(out.Sboms)
	return out, nil
}
