// Copyright (c) 2026 Vincent Palmer. All rights reserved.
package bdd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/google/uuid"
	"github.com/transparenz/transparenz-server-oss/internal/models"
	"github.com/transparenz/transparenz-server-oss/internal/services"
	"go.uber.org/zap"
)

func RegisterExtendedSteps(s *godog.ScenarioContext) {
	// Signing key lifecycle: properly signed events
	s.Step(`^a compliance event signed with the active key exists$`, extSeedSignedEventWithActiveKey)
	s.Step(`^a second compliance event signed with the active key exists$`, extSeedSecondSignedEvent)

	// Export with date range
	s.Step(`^I export the audit trail from "([^"]*)" to "([^"]*)" as CSV$`, extExportCSVDateRange)
	s.Step(`^I export the audit trail as PDF with template "([^"]*)"$`, extExportPDFTemplate)

	// ENISA lifecycle
	s.Step(`^I get ENISA submission with ID "([^"]*)"$`, extGetEnisaByID)
	s.Step(`^the response should contain 0 ENISA submissions$`, extAssertZeroEnisaSubmissions)

	// Edge cases: SBOM deletion by ID
	s.Step(`^I delete SBOM with ID "([^"]*)"$`, extDeleteSBOMByID)

	// Edge cases: pagination
	s.Step(`^I list scans with limit (\d+)$`, extListScansWithLimit)
	s.Step(`^I list VEX statements with limit (\d+)$`, extListVEXWithLimit)

	// Edge cases: VEX empty body
	s.Step(`^I create a VEX statement with empty body$`, extVEXEmptyBody)

	// Edge cases: SBOM webhook management
	s.Step(`^I list SBOM webhooks$`, extListSBOMWebhooks)
	s.Step(`^I delete SBOM webhook "([^"]*)"$`, extDeleteSBOMWebhookByName)

	// Edge cases: sovereign feed source
	s.Step(`^the vulnerability "([^"]*)" has sovereign feed source "([^"]*)"$`, extSetSovereignFeedSource)
}

// signingSvc returns a SigningService using the same key path as the BDD app.
func signingSvc() *services.SigningService {
	keyPath := filepath.Join(os.TempDir(), "bdd-signing-key")
	return services.NewSigningService(tc().DB, zap.NewNop(), keyPath)
}

// --- Signed Event Seeding (uses real Ed25519 signatures) ---

func extSeedSignedEventWithActiveKey() error {
	orgID := uuid.MustParse(tc().OrgID)
	event := &models.ComplianceEvent{
		ID:        uuid.New(),
		OrgID:     orgID,
		EventType: "vulnerability_discovered",
		Severity:  "high",
		Cve:       "CVE-2026-SIGNED",
		Timestamp: time.Now(),
		Metadata:  models.JSONMap{"source": "signing-lifecycle-test"},
	}

	svc := signingSvc()
	if err := svc.SignEvent(event); err != nil {
		return fmt.Errorf("failed to sign event: %w", err)
	}
	if err := tc().DB.Create(event).Error; err != nil {
		return fmt.Errorf("failed to create signed event: %w", err)
	}
	return nil
}

func extSeedSecondSignedEvent() error {
	orgID := uuid.MustParse(tc().OrgID)
	event := &models.ComplianceEvent{
		ID:        uuid.New(),
		OrgID:     orgID,
		EventType: "sla_violation",
		Severity:  "critical",
		Cve:       "CVE-2026-SIGNED-2",
		Timestamp: time.Now(),
		Metadata:  models.JSONMap{"source": "signing-lifecycle-test"},
	}

	svc := signingSvc()
	if err := svc.SignEvent(event); err != nil {
		return fmt.Errorf("failed to sign second event: %w", err)
	}
	if err := tc().DB.Create(event).Error; err != nil {
		return fmt.Errorf("failed to create second signed event: %w", err)
	}
	return nil
}

// --- Export with Date Range ---

func extExportCSVDateRange(start, end string) error {
	url := fmt.Sprintf("/api/export/audit?format=csv&start=%s&end=%s", start, end)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.ComplianceOfficerToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func extExportPDFTemplate(template string) error {
	url := fmt.Sprintf("/api/export/audit?format=pdf&template=%s", template)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.ComplianceOfficerToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

// --- ENISA Lifecycle ---

func extGetEnisaByID(id string) error {
	req := httptest.NewRequest(http.MethodGet, "/api/enisa/submissions/"+id, nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func extAssertZeroEnisaSubmissions() error {
	if lastResponse == nil {
		return fmt.Errorf("no response recorded")
	}
	var body struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal(lastResponse.Body.Bytes(), &body); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	if body.Count != 0 {
		return fmt.Errorf("expected 0 ENISA submissions, got %d", body.Count)
	}
	return nil
}

// --- Edge Cases: SBOM Deletion ---

func extDeleteSBOMByID(id string) error {
	req := httptest.NewRequest(http.MethodDelete, "/api/sboms/"+id, nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

// --- Edge Cases: Pagination ---

func extListScansWithLimit(limit int) error {
	url := fmt.Sprintf("/api/scans?limit=%d", limit)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func extListVEXWithLimit(limit int) error {
	url := fmt.Sprintf("/api/vex?limit=%d", limit)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

// --- Edge Cases: VEX Empty Body ---

func extVEXEmptyBody() error {
	req := httptest.NewRequest(http.MethodPost, "/api/vex", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	req.Header.Set("Content-Type", "application/json")
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

// --- Edge Cases: SBOM Webhook Management ---

func extListSBOMWebhooks() error {
	req := httptest.NewRequest(http.MethodGet, "/api/sbom/webhooks", nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func extDeleteSBOMWebhookByName(name string) error {
	// First list to find the webhook by name, then delete by ID
	listReq := httptest.NewRequest(http.MethodGet, "/api/sbom/webhooks", nil)
	listReq.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	listResp := httptest.NewRecorder()
	tc().Router.ServeHTTP(listResp, listReq)

	var listBody struct {
		Data []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(listResp.Body.Bytes(), &listBody); err != nil {
		return fmt.Errorf("failed to parse webhook list: %w", err)
	}

	for _, wh := range listBody.Data {
		if wh.Name == name {
			req := httptest.NewRequest(http.MethodDelete, "/api/sbom/webhooks/"+wh.ID, nil)
			req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
			lastResponse = httptest.NewRecorder()
			tc().Router.ServeHTTP(lastResponse, req)
			return nil
		}
	}
	return fmt.Errorf("SBOM webhook %q not found in list", name)
}

// --- Edge Cases: Sovereign Feed Source ---

func extSetSovereignFeedSource(cve, source string) error {
	orgID := uuid.MustParse(tc().OrgID)
	return tc().DB.Model(&models.Vulnerability{}).
		Where("org_id = ? AND cve = ?", orgID, cve).
		Update("sovereign_feed_source", source).Error
}
