// Copyright (c) 2026 Vincent Palmer. All rights reserved.
package bdd

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"time"

	"github.com/cucumber/godog"
)

var lastSbomID string
var lastSbomWebhookID string
var lastSbomWebhookSecret string
var lastSbomWebhookSigningSecret string
var sbomUploadCount int

func RegisterSbomSteps(s *godog.ScenarioContext) {
	s.Step(`^I upload a "([^"]*)" SBOM file named "([^"]*)"$`, sbomUploadFile)
	s.Step(`^the SBOM should be listed for the organization$`, sbomAssertListed)
	s.Step(`^I list SBOMs$`, sbomListSboms)
	s.Step(`^I get SBOM with ID from the last upload$`, sbomGetByID)
	s.Step(`^I download the last uploaded SBOM$`, sbomDownload)
	s.Step(`^the response should contain the SBOM document$`, sbomAssertDocument)
	s.Step(`^I delete the last uploaded SBOM$`, sbomDelete)
	s.Step(`^the SBOM should no longer be listed$`, sbomAssertNotListed)
	s.Step(`^I create an SBOM webhook named "([^"]*)"$`, sbomCreateWebhook)
	s.Step(`^I send an SBOM via webhook "([^"]*)"$`, sbomSendViaWebhook)
	s.Step(`^I upload a file of (\d+) bytes as SBOM$`, sbomUploadOversized)
}

func sbomBuildUploadBody(format, filename string) (*bytes.Buffer, string) {
	var sbomContent string
	switch format {
	case "cyclonedx":
		sbomContent = fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[{"name":"test-pkg-%s","version":"1.0.0","type":"library"}]}`, filename)
	case "spdx":
		sbomContent = fmt.Sprintf(`{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","name":"test-pkg-%s","SPDXID":"SPDXRef-DOCUMENT","creationInfo":{"created":"2025-01-01T00:00:00Z","creators":["Tool: test"]},"packages":[{"name":"test-pkg-%s","SPDXID":"SPDXRef-Package","downloadLocation":"NONE"}]}`, filename, filename)
	default:
		sbomContent = `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1}`
	}
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("file", filename)
	_, _ = part.Write([]byte(sbomContent))
	_ = writer.Close()
	return &buf, writer.FormDataContentType()
}

func sbomUploadFile(format, filename string) error {
	body, contentType := sbomBuildUploadBody(format, filename)
	req := httptest.NewRequest(http.MethodPost, "/api/sboms/upload", body)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	req.Header.Set("Content-Type", contentType)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	if lastResponse.Code == http.StatusCreated {
		sbomUploadCount++
		var resp struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(lastResponse.Body.Bytes(), &resp); err == nil {
			lastSbomID = resp.ID
		}
	}
	return nil
}

func sbomUploadOversized(size int) error {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("file", "oversized.cdx.json")
	_, _ = part.Write(make([]byte, size))
	_ = writer.Close()
	req := httptest.NewRequest(http.MethodPost, "/api/sboms/upload", &buf)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func sbomAssertListed() error {
	req := httptest.NewRequest(http.MethodGet, "/api/sboms", nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	resp := httptest.NewRecorder()
	tc().Router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		return fmt.Errorf("list returned %d: %s", resp.Code, resp.Body.String())
	}
	var listResp struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &listResp); err != nil {
		return fmt.Errorf("failed to parse list response: %w", err)
	}
	if listResp.Count < 1 {
		return fmt.Errorf("expected at least 1 SBOM in list, got %d", listResp.Count)
	}
	return nil
}

func sbomListSboms() error {
	req := httptest.NewRequest(http.MethodGet, "/api/sboms", nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func sbomGetByID() error {
	req := httptest.NewRequest(http.MethodGet, "/api/sboms/"+lastSbomID, nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func sbomDownload() error {
	req := httptest.NewRequest(http.MethodGet, "/api/sboms/"+lastSbomID+"/download", nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func sbomAssertDocument() error {
	if lastResponse == nil {
		return fmt.Errorf("no response recorded")
	}
	body := lastResponse.Body.String()
	if !strings.Contains(body, "bomFormat") && !strings.Contains(body, "spdxVersion") && !strings.Contains(body, "test-pkg") {
		return fmt.Errorf("response does not contain SBOM document: %s", body)
	}
	return nil
}

func sbomDelete() error {
	req := httptest.NewRequest(http.MethodDelete, "/api/sboms/"+lastSbomID, nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func sbomAssertNotListed() error {
	req := httptest.NewRequest(http.MethodGet, "/api/sboms", nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	resp := httptest.NewRecorder()
	tc().Router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		return fmt.Errorf("list returned %d: %s", resp.Code, resp.Body.String())
	}
	var listResp struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &listResp); err != nil {
		return fmt.Errorf("failed to parse list response: %w", err)
	}
	if listResp.Count >= sbomUploadCount {
		return fmt.Errorf("expected fewer than %d SBOMs, got %d", sbomUploadCount, listResp.Count)
	}
	return nil
}

func sbomCreateWebhook(name string) error {
	body := fmt.Sprintf(`{"name":"%s","actions":{"trigger_scan":true,"broadcast_alerts":true,"emit_otel":true}}`, name)
	req := httptest.NewRequest(http.MethodPost, "/api/sbom/webhooks", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	req.Header.Set("Content-Type", "application/json")
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	if lastResponse.Code == http.StatusCreated {
		var resp struct {
			ID            string `json:"id"`
			Secret        string `json:"secret"`
			SigningSecret string `json:"signing_secret"`
		}
		if err := json.Unmarshal(lastResponse.Body.Bytes(), &resp); err == nil {
			lastSbomWebhookID = resp.ID
			lastSbomWebhookSecret = resp.Secret
			lastSbomWebhookSigningSecret = resp.SigningSecret
		}
	}
	return nil
}

func sbomSendViaWebhook(webhookName string) error {
	sbomContent := `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[{"name":"webhook-pkg","version":"2.0.0","type":"library"}]}`
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("file", "webhook-upload.cdx")
	_, _ = part.Write([]byte(sbomContent))
	_ = writer.Close()
	url := "/api/v1/sbom/webhook/" + lastSbomWebhookID
	req := httptest.NewRequest(http.MethodPost, url, &buf)
	req.Header.Set("X-SBOM-Token", lastSbomWebhookSecret)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	if lastSbomWebhookSigningSecret != "" {
		mac := hmac.New(sha256.New, []byte(lastSbomWebhookSigningSecret))
		mac.Write(buf.Bytes())
		req.Header.Set("X-Webhook-Signature", hex.EncodeToString(mac.Sum(nil)))
		req.Header.Set("X-Webhook-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	}
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	if lastResponse.Code == http.StatusCreated {
		sbomUploadCount++
	}
	return nil
}
