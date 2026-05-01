// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package services

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
)

type SigningService struct {
	db            *gorm.DB
	logger        *zap.Logger
	serverPrivKey ed25519.PrivateKey
	serverPubKey  ed25519.PublicKey
	serverKeyID   uuid.UUID
}

func NewSigningService(db *gorm.DB, logger *zap.Logger, keyPath string) *SigningService {
	privKey, pubKey := loadOrCreateServerKey(keyPath, logger)
	s := &SigningService{
		db:            db,
		logger:        logger,
		serverPrivKey: privKey,
		serverPubKey:  pubKey,
		serverKeyID:   uuid.NewSHA1(uuid.NameSpaceDNS, pubKey),
	}
	return s
}

func loadOrCreateServerKey(keyPath string, logger *zap.Logger) (ed25519.PrivateKey, ed25519.PublicKey) {
	if data, err := os.ReadFile(keyPath); err == nil { //nolint:gosec
		if len(data) == ed25519.SeedSize {
			seed := make([]byte, ed25519.SeedSize)
			copy(seed, data)
			privKey := ed25519.NewKeyFromSeed(seed)
			logger.Info("loaded Ed25519 server signing key", zap.String("path", keyPath))
			return privKey, privKey.Public().(ed25519.PublicKey)
		}
		logger.Warn("invalid signing key file size, regenerating", zap.Int("bytes", len(data)))
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		logger.Fatal("failed to generate Ed25519 server key", zap.Error(err))
	}

	seed := make([]byte, ed25519.SeedSize)
	copy(seed, priv[:ed25519.SeedSize])

	dir := filepath.Dir(keyPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		logger.Warn("failed to create signing key directory", zap.String("dir", dir), zap.Error(err))
	} else {
		if err := os.WriteFile(keyPath, seed, 0600); err != nil {
			logger.Warn("failed to persist generated signing key", zap.String("path", keyPath), zap.Error(err))
		} else {
			logger.Info("generated and saved new Ed25519 server signing key", zap.String("path", keyPath))
		}
	}

	return priv, pub
}

func (s *SigningService) ServerPublicKey() ed25519.PublicKey {
	return s.serverPubKey
}

func (s *SigningService) ServerKeyID() uuid.UUID {
	return s.serverKeyID
}

func (s *SigningService) GenerateKeyPair(orgID uuid.UUID) (publicKey string, privateKey ed25519.PrivateKey, keyID uuid.UUID, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, uuid.Nil, fmt.Errorf("generate ed25519 key: %w", err)
	}

	pubBytes := make([]byte, ed25519.PublicKeySize)
	copy(pubBytes, pub)

	key := &models.SigningKey{
		ID:           uuid.New(),
		OrgID:        orgID,
		PublicKey:    hex.EncodeToString(pubBytes),
		KeyAlgorithm: "ed25519",
	}

	if err := s.db.Create(key).Error; err != nil {
		return "", nil, uuid.Nil, fmt.Errorf("store signing key: %w", err)
	}

	return hex.EncodeToString(pubBytes), priv, key.ID, nil
}

func (s *SigningService) GetActiveKey(orgID uuid.UUID) (*models.SigningKey, error) {
	var key models.SigningKey
	err := s.db.Where("org_id = ? AND revoked_at IS NULL", orgID).Order("created_at DESC").First(&key).Error
	if err != nil {
		return nil, fmt.Errorf("no active signing key for org: %w", err)
	}
	return &key, nil
}

func (s *SigningService) SignEventWithKey(event *models.ComplianceEvent, privateKey ed25519.PrivateKey) error {
	payload := map[string]interface{}{
		"event_type":            event.EventType,
		"severity":              event.Severity,
		"cve":                   event.Cve,
		"reported_to_authority": event.ReportedToAuthority,
		"timestamp":             event.Timestamp.Format(time.RFC3339Nano),
		"metadata":              event.Metadata,
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	hash := sha256.Sum256(payloadJSON)
	eventHash := hex.EncodeToString(hash[:])

	previousHash := event.PreviousEventHash

	signData := append([]byte(previousHash), payloadJSON...)
	signature := ed25519.Sign(privateKey, signData)
	event.Signature = hex.EncodeToString(signature)
	event.EventHash = eventHash
	event.PreviousEventHash = previousHash

	return nil
}

func (s *SigningService) SignEvent(event *models.ComplianceEvent) error {
	return s.SignEventWithKey(event, s.serverPrivKey)
}

func (s *SigningService) VerifyEventChain(orgID uuid.UUID, start, end time.Time) ([]EventVerification, error) {
	var events []models.ComplianceEvent
	err := s.db.Where("org_id = ? AND timestamp >= ? AND timestamp <= ? AND event_hash IS NOT NULL", orgID, start, end).
		Order("timestamp ASC").Find(&events).Error
	if err != nil {
		return nil, fmt.Errorf("query events: %w", err)
	}

	if len(events) == 0 {
		return nil, nil
	}

	results := make([]EventVerification, len(events))
	for i, event := range events {
		verified := true
		reason := ""

		if i > 0 && event.PreviousEventHash != events[i-1].EventHash {
			verified = false
			reason = "chain broken: previous hash mismatch"
		}

		if event.Signature == "" {
			verified = false
			if reason == "" {
				reason = "unsigned event"
			}
		}

		if verified && event.Signature != "" {
			var keys []models.SigningKey
			if keyErr := s.db.Where("org_id = ? AND revoked_at IS NULL", orgID).Order("created_at DESC").Find(&keys).Error; keyErr != nil || len(keys) == 0 {
				verified = false
				reason = "no signing keys found"
			} else {
				payload := map[string]interface{}{
					"event_type":            event.EventType,
					"severity":              event.Severity,
					"cve":                   event.Cve,
					"reported_to_authority": event.ReportedToAuthority,
					"timestamp":             event.Timestamp.Format(time.RFC3339Nano),
					"metadata":              event.Metadata,
				}
				payloadJSON, marshErr := json.Marshal(payload)
				if marshErr != nil {
					verified = false
					reason = "failed to reconstruct payload"
				} else {
					signData := append([]byte(event.PreviousEventHash), payloadJSON...)
					sigBytes, sigErr := hex.DecodeString(event.Signature)
					if sigErr != nil {
						verified = false
						reason = "invalid signature encoding"
					} else {
						sigVerified := false
						for _, k := range keys {
							pubKeyBytes, decErr := hex.DecodeString(k.PublicKey)
							if decErr != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
								continue
							}
							if ed25519.Verify(pubKeyBytes, signData, sigBytes) {
								sigVerified = true
								break
							}
						}
						if !sigVerified {
							verified = false
							reason = "signature verification failed"
						}
					}
				}
			}
		}

		results[i] = EventVerification{
			EventID:  event.ID,
			Hash:     event.EventHash,
			Verified: verified,
			Reason:   reason,
		}
	}

	return results, nil
}

type EventVerification struct {
	EventID  uuid.UUID `json:"event_id"`
	Hash     string    `json:"hash"`
	Verified bool      `json:"verified"`
	Reason   string    `json:"reason,omitempty"`
}

// RevokeKey marks a signing key as revoked for the given organisation.
func (s *SigningService) RevokeKey(ctx context.Context, orgID string, keyID string) error {
	result := s.db.WithContext(ctx).
		Model(&models.SigningKey{}).
		Where("id = ? AND org_id = ? AND revoked_at IS NULL", keyID, orgID).
		Update("revoked_at", time.Now())
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		// Either not found or already revoked — check which
		var count int64
		s.db.WithContext(ctx).Model(&models.SigningKey{}).
			Where("id = ? AND org_id = ?", keyID, orgID).Count(&count)
		if count == 0 {
			return fmt.Errorf("signing key not found: %s", keyID)
		}
		return fmt.Errorf("signing key already revoked: %s", keyID)
	}
	return nil
}
