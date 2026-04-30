// Copyright (c) 2026 Vincent Palmer. All rights reserved.
package bdd

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/google/uuid"
	"github.com/transparenz/transparenz-server-oss/internal/models"
)

// auditEventID stores the event ID for tampering scenarios.
var auditEventID uuid.UUID

func RegisterAuditTamperSteps(s *godog.ScenarioContext) {
	s.Step(`^a signed compliance event exists for the organization$`, tamperSeedSignedEvent)
	s.Step(`^two consecutive signed compliance events exist for the organization$`, tamperSeedTwoEvents)
	s.Step(`^the event's hash is tampered with$`, tamperCorruptHash)
	s.Step(`^the second event's previous hash is corrupted$`, tamperCorruptChainLink)
	s.Step(`^the audit chain should be verified$`, tamperAssertVerified)
	s.Step(`^the audit chain should NOT be verified$`, tamperAssertNotVerified)
}

func tamperSeedSignedEvent() error {
	orgID := uuid.MustParse(tc().OrgID)

	// Generate a signing key for the org
	key := models.SigningKey{
		ID:           uuid.New(),
		OrgID:        orgID,
		PublicKey:    hex.EncodeToString(make([]byte, 32)), // placeholder
		KeyAlgorithm: "ed25519",
	}
	if err := tc().DB.Create(&key).Error; err != nil {
		return fmt.Errorf("create signing key: %w", err)
	}

	event := models.ComplianceEvent{
		ID:                uuid.New(),
		OrgID:             orgID,
		EventType:         "vulnerability_discovered",
		Severity:          "high",
		Cve:               "CVE-2026-AUDIT",
		Timestamp:         time.Now(),
		Metadata:          models.JSONMap{"source": "audit-tamper-test"},
		PreviousEventHash: "",
		EventHash:         "a" + strings.Repeat("0", 63), // fake hash
		Signature:         "b" + strings.Repeat("0", 127), // fake signature
	}
	if err := tc().DB.Create(&event).Error; err != nil {
		return fmt.Errorf("create event: %w", err)
	}
	auditEventID = event.ID
	return nil
}

func tamperSeedTwoEvents() error {
	orgID := uuid.MustParse(tc().OrgID)

	key := models.SigningKey{
		ID:           uuid.New(),
		OrgID:        orgID,
		PublicKey:    hex.EncodeToString(make([]byte, 32)),
		KeyAlgorithm: "ed25519",
	}
	if err := tc().DB.Create(&key).Error; err != nil {
		return fmt.Errorf("create signing key: %w", err)
	}

	event1Hash := "a" + strings.Repeat("0", 63)
	event1 := models.ComplianceEvent{
		ID:                uuid.New(),
		OrgID:             orgID,
		EventType:         "vulnerability_discovered",
		Severity:          "critical",
		Cve:               "CVE-2026-CHAIN-1",
		Timestamp:         time.Now().Add(-1 * time.Hour),
		Metadata:          models.JSONMap{"source": "chain-test"},
		PreviousEventHash: "",
		EventHash:         event1Hash,
		Signature:         "b" + strings.Repeat("0", 127),
	}
	if err := tc().DB.Create(&event1).Error; err != nil {
		return fmt.Errorf("create event 1: %w", err)
	}

	event2 := models.ComplianceEvent{
		ID:                uuid.New(),
		OrgID:             orgID,
		EventType:         "sla_violation",
		Severity:          "high",
		Cve:               "CVE-2026-CHAIN-1",
		Timestamp:         time.Now(),
		Metadata:          models.JSONMap{"source": "chain-test"},
		PreviousEventHash: event1Hash,
		EventHash:         "c" + strings.Repeat("0", 63),
		Signature:         "d" + strings.Repeat("0", 127),
	}
	if err := tc().DB.Create(&event2).Error; err != nil {
		return fmt.Errorf("create event 2: %w", err)
	}
	auditEventID = event2.ID
	return nil
}

func tamperCorruptHash() error {
	// Modify the event hash in the database to simulate tampering
	return tc().DB.Model(&models.ComplianceEvent{}).
		Where("id = ?", auditEventID).
		Update("event_hash", "TAMPERED_HASH_VALUE").Error
}

func tamperCorruptChainLink() error {
	// Modify the second event's previous_hash to break the chain
	return tc().DB.Model(&models.ComplianceEvent{}).
		Where("id = ?", auditEventID).
		Update("previous_event_hash", "BROKEN_CHAIN_LINK").Error
}

func tamperAssertVerified() error {
	if lastResponse == nil {
		return fmt.Errorf("no response recorded")
	}
	var body struct {
		Verified bool `json:"verified"`
	}
	if err := json.Unmarshal(lastResponse.Body.Bytes(), &body); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	if !body.Verified {
		return fmt.Errorf("expected audit chain to be verified, but it was not: %s", lastResponse.Body.String())
	}
	return nil
}

func tamperAssertNotVerified() error {
	if lastResponse == nil {
		return fmt.Errorf("no response recorded")
	}
	var body struct {
		Verified bool `json:"verified"`
	}
	if err := json.Unmarshal(lastResponse.Body.Bytes(), &body); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	if body.Verified {
		return fmt.Errorf("expected audit chain to NOT be verified, but it was: %s", lastResponse.Body.String())
	}
	return nil
}
