// SPDX-FileCopyrightText: 2026 Vincent Palmer
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Transparenz, an open-source CRA compliance server.
// It is licensed under the GNU Affero General Public License v3.0; see LICENSE.

package services

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/vincents-ai/transparenz-server-oss/internal/testutil"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
)

// The audit chain is the evidence this product offers that a compliance event
// happened and has not been altered. It had NO test that verified a chain: the
// handler tests in internal/api/rest cover parameter validation only (no org,
// missing start, missing end), so nothing exercised verification at all.
//
// These tests sign real events with a real key and then tamper with the stored
// rows, because "the chain verifies" is only meaningful if it fails when the
// chain is broken.
func setupAuditChain(t *testing.T) (*gorm.DB, *SigningService, uuid.UUID, ed25519.PrivateKey) {
	t.Helper()
	db := testutil.SetupTestDB(t)

	ddl := []string{
		`CREATE TABLE IF NOT EXISTS "compliance"."compliance_events" (
			id text PRIMARY KEY, org_id text NOT NULL, event_type text NOT NULL,
			severity text NOT NULL, cve text DEFAULT '', reported_to_authority text DEFAULT '',
			timestamp datetime, metadata text DEFAULT '{}', signature text DEFAULT '',
			signing_key_id text, previous_event_hash text DEFAULT '',
			event_hash text DEFAULT '', created_at datetime
		)`,
		`CREATE TABLE IF NOT EXISTS "compliance"."signing_keys" (
			id text PRIMARY KEY, org_id text NOT NULL, public_key text NOT NULL,
			key_algorithm text NOT NULL DEFAULT 'ed25519', created_at datetime, revoked_at datetime
		)`,
	}
	for _, d := range ddl {
		require.NoError(t, db.Exec(d).Error)
	}

	org := testutil.CreateTestOrg(t, db)
	svc := NewSigningService(db, zap.NewNop(), t.TempDir()+"/audit-test.key")

	// GenerateKeyPair stores the public half itself; signing with the private half
	// it returns is what a filer would do.
	_, priv, _, err := svc.GenerateKeyPair(org.ID)
	require.NoError(t, err)

	// created_at must be set for the "most recent key" lookup to order sanely.
	require.NoError(t, db.Model(&models.SigningKey{}).Where("org_id = ?", org.ID).
		Update("created_at", time.Now().UTC()).Error)

	// The per-org key is registered above, so verification finds a key it can use.
	// Tests sign through SignEventWithKey with this private half rather than
	// through a hook on the service: production code does not grow a settable key
	// for a test's convenience.
	return db, svc, org.ID, priv
}

// appendEvent chains and persists one event, as the compliance handler does.
func appendEvent(t *testing.T, db *gorm.DB, svc *SigningService, priv ed25519.PrivateKey,
	orgID uuid.UUID, eventType, cve string, at time.Time, previousHash string) models.ComplianceEvent {
	t.Helper()

	ev := models.ComplianceEvent{
		ID:        uuid.New(),
		OrgID:     orgID,
		EventType: eventType,
		Severity:  "high",
		Cve:       cve,
		Timestamp: at,
		Metadata:  models.JSONMap{"source": "test"},
	}
	ev.PreviousEventHash = previousHash
	require.NoError(t, svc.SignEventWithKey(&ev, priv))
	require.NoError(t, db.Create(&ev).Error)
	return ev
}

func TestAuditChainVerifiesAndDetectsTampering(t *testing.T) {
	db, svc, orgID, priv := setupAuditChain(t)
	base := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	window := func() (time.Time, time.Time) {
		return base.Add(-time.Hour), base.Add(24 * time.Hour)
	}

	first := appendEvent(t, db, svc, priv, orgID, "sbom_uploaded", "", base, "")
	second := appendEvent(t, db, svc, priv, orgID, "vulnerability_matched", "CVE-2026-0001", base.Add(time.Minute), first.EventHash)
	third := appendEvent(t, db, svc, priv, orgID, "sla_breach", "CVE-2026-0002", base.Add(2*time.Minute), second.EventHash)

	t.Run("an untouched chain verifies", func(t *testing.T) {
		start, end := window()
		results, err := svc.VerifyEventChain(orgID, start, end)
		require.NoError(t, err)
		require.Len(t, results, 3)
		for _, r := range results {
			assert.True(t, r.Verified, "event %s should verify: %s", r.EventID, r.Reason)
		}
	})

	t.Run("an altered payload fails verification", func(t *testing.T) {
		// The signature covers the payload, so changing what the event says must
		// break it. This is the property the whole feature exists for.
		require.NoError(t, db.Model(&models.ComplianceEvent{}).
			Where("id = ?", second.ID).Update("cve", "CVE-2026-9999").Error)

		start, end := window()
		results, err := svc.VerifyEventChain(orgID, start, end)
		require.NoError(t, err)

		var target *EventVerification
		for i := range results {
			if results[i].EventID == second.ID {
				target = &results[i]
			}
		}
		require.NotNil(t, target)
		assert.False(t, target.Verified, "an edited event must not verify")
		assert.NotEmpty(t, target.Reason)
	})

	t.Run("a deleted event breaks the chain at the next link", func(t *testing.T) {
		require.NoError(t, db.Where("id = ?", second.ID).Delete(&models.ComplianceEvent{}).Error)

		start, end := window()
		results, err := svc.VerifyEventChain(orgID, start, end)
		require.NoError(t, err)
		require.Len(t, results, 2, "the remaining events are the first and the third")

		var lastVerified bool
		for _, r := range results {
			if r.EventID == third.ID {
				lastVerified = r.Verified
				assert.Contains(t, r.Reason, "previous hash mismatch")
			}
		}
		assert.False(t, lastVerified,
			"removing an event must break the link recorded in the following one")
	})

}

// An unsigned event is caught even when the chain links are intact, so this is a
// separate test: after the deletion above, the reason for any later event is the
// broken link, which would hide whether the signature check works at all.
func TestAuditChainDetectsAnUnsignedEventInAnIntactChain(t *testing.T) {
	db, svc, orgID, priv := setupAuditChain(t)
	base := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)

	first := appendEvent(t, db, svc, priv, orgID, "sbom_uploaded", "", base, "")

	// Correct link, no signature: the chain is structurally fine and only the
	// signature is missing.
	unsigned := models.ComplianceEvent{
		ID: uuid.New(), OrgID: orgID, EventType: "vulnerability_matched",
		Severity: "high", Timestamp: base.Add(time.Minute), Metadata: models.JSONMap{},
		PreviousEventHash: first.EventHash, EventHash: "deadbeef",
	}
	require.NoError(t, db.Create(&unsigned).Error)

	results, err := svc.VerifyEventChain(orgID, base.Add(-time.Hour), base.Add(24*time.Hour))
	require.NoError(t, err)
	require.Len(t, results, 2)

	for _, r := range results {
		if r.EventID == unsigned.ID {
			assert.False(t, r.Verified)
			assert.Contains(t, r.Reason, "unsigned")
		}
	}
}

// The limit, asserted rather than implied: removing the LAST event leaves a chain
// with nothing to contradict it, so verification still reports success. Detecting
// that needs something outside the database — a published head hash, an exported
// manifest, or a periodic anchor — and this product does not have one yet.
//
// The test exists so the gap is a decision somebody made after seeing it, not an
// assumption that the chain detects everything.
func TestAuditChainCannotDetectTruncationOfTheTail(t *testing.T) {
	db, svc, orgID, priv := setupAuditChain(t)
	base := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

	first := appendEvent(t, db, svc, priv, orgID, "sbom_uploaded", "", base, "")
	second := appendEvent(t, db, svc, priv, orgID, "vulnerability_matched", "CVE-2026-0001", base.Add(time.Minute), first.EventHash)
	require.NotEmpty(t, second.EventHash)

	require.NoError(t, db.Where("id = ?", second.ID).Delete(&models.ComplianceEvent{}).Error)

	results, err := svc.VerifyEventChain(orgID, base.Add(-time.Hour), base.Add(24*time.Hour))
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.True(t, results[0].Verified,
		"with the tail removed there is no later event whose previous_event_hash "+
			"could disagree, so the chain still verifies. Do not describe this "+
			"verification as proof that nothing was removed.")
}
