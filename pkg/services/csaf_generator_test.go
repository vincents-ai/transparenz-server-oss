package services

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
)

func testOrgID() uuid.UUID {
	return uuid.MustParse("00000000-0000-0000-0000-000000000001")
}

func TestGeneratePerCVE_WithFeedData(t *testing.T) {
	orgID := testOrgID()
	cvss := 9.8
	vuln := models.Vulnerability{
		ID:           uuid.New(),
		OrgID:        orgID,
		Cve:          "CVE-2024-1001",
		CvssScore:    &cvss,
		Severity:     "critical",
		DiscoveredAt: time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC),
	}

	bsiCompliant := true
	feed := models.VulnerabilityFeed{
		ID:                  uuid.New(),
		Cve:                 "CVE-2024-1001",
		KevExploited:        true,
		EnisaEuvdID:         "EUVD-12345",
		EnisaSeverity:       "critical",
		BsiAdvisoryID:       "BSI-2024-001",
		BsiTr03116Compliant: &bsiCompliant,
	}

	feedMap := map[string]*models.VulnerabilityFeed{
		"CVE-2024-1001": &feed,
	}

	doc := buildCSAFDocumentForTest(orgID, []models.Vulnerability{vuln}, feedMap)

	if doc.Document.Title == "" {
		t.Fatal("expected document title to be set")
	}
	if doc.Document.Category != "csaf_2.0" {
		t.Fatalf("expected category csaf_2.0, got %s", doc.Document.Category)
	}
	if len(doc.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(doc.Vulnerabilities))
	}

	csafVuln := doc.Vulnerabilities[0]
	if csafVuln.CVE != "CVE-2024-1001" {
		t.Fatalf("expected CVE CVE-2024-1001, got %s", csafVuln.CVE)
	}
	if len(csafVuln.Notes) == 0 {
		t.Fatal("expected notes from feed enrichment")
	}

	hasEnisaNote := false
	hasBsiNote := false
	for _, n := range csafVuln.Notes {
		if n.Title == "ENISA Severity" {
			hasEnisaNote = true
		}
		if n.Title == "BSI TR-03116 Compliant" {
			hasBsiNote = true
		}
	}
	if !hasEnisaNote {
		t.Fatal("expected ENISA severity note from feed")
	}
	if !hasBsiNote {
		t.Fatal("expected BSI TR-03116 compliant note from feed")
	}

	hasEnisaID := false
	hasBsiID := false
	for _, id := range csafVuln.IDs {
		if id.SystemName == "ENISA EUVD" && id.Text == "EUVD-12345" {
			hasEnisaID = true
		}
		if id.SystemName == "BSI" && id.Text == "BSI-2024-001" {
			hasBsiID = true
		}
	}
	if !hasEnisaID {
		t.Fatal("expected ENISA EUVD ID from feed")
	}
	if !hasBsiID {
		t.Fatal("expected BSI advisory ID from feed")
	}
}

func TestGeneratePerCVE_WithoutFeedData(t *testing.T) {
	orgID := testOrgID()
	cvss := 7.5
	vuln := models.Vulnerability{
		ID:           uuid.New(),
		OrgID:        orgID,
		Cve:          "CVE-2024-2000",
		CvssScore:    &cvss,
		Severity:     "high",
		DiscoveredAt: time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC),
	}

	feedMap := map[string]*models.VulnerabilityFeed{}

	doc := buildCSAFDocumentForTest(orgID, []models.Vulnerability{vuln}, feedMap)

	if len(doc.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(doc.Vulnerabilities))
	}

	csafVuln := doc.Vulnerabilities[0]
	if csafVuln.CVE != "CVE-2024-2000" {
		t.Fatalf("expected CVE CVE-2024-2000, got %s", csafVuln.CVE)
	}

	hasEnisaNote := false
	for _, n := range csafVuln.Notes {
		if n.Title == "ENISA Severity" {
			hasEnisaNote = true
		}
	}
	if hasEnisaNote {
		t.Fatal("expected no ENISA severity note without feed")
	}

	for _, id := range csafVuln.IDs {
		if id.SystemName == "ENISA EUVD" || id.SystemName == "BSI" {
			t.Fatalf("expected no feed IDs, got %s: %s", id.SystemName, id.Text)
		}
	}
}

func TestBuildVulnerability_WithFeedEnrichment(t *testing.T) {
	orgID := testOrgID()
	cvss := 8.5
	vuln := models.Vulnerability{
		ID:           uuid.New(),
		OrgID:        orgID,
		Cve:          "CVE-2024-3000",
		CvssScore:    &cvss,
		Severity:     "high",
		DiscoveredAt: time.Date(2024, 5, 10, 0, 0, 0, 0, time.UTC),
	}

	kevDate := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	feed := models.VulnerabilityFeed{
		ID:            uuid.New(),
		Cve:           "CVE-2024-3000",
		KevExploited:  true,
		KevDateAdded:  &kevDate,
		EnisaEuvdID:   "EUVD-99999",
		EnisaSeverity: "high",
	}

	feedMap := map[string]*models.VulnerabilityFeed{
		"CVE-2024-3000": &feed,
	}

	doc := buildCSAFDocumentForTest(orgID, []models.Vulnerability{vuln}, feedMap)

	if len(doc.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(doc.Vulnerabilities))
	}

	csafVuln := doc.Vulnerabilities[0]

	if len(csafVuln.Threats) != 1 {
		t.Fatalf("expected 1 threat (KEV from feed), got %d", len(csafVuln.Threats))
	}
	if csafVuln.Threats[0].Category != "exploit_status" {
		t.Fatalf("expected exploit_status threat, got %s", csafVuln.Threats[0].Category)
	}
	if csafVuln.Threats[0].Date != kevDate.Format(time.RFC3339) {
		t.Fatalf("expected date %s, got %s", kevDate.Format(time.RFC3339), csafVuln.Threats[0].Date)
	}

	if len(csafVuln.Scores) != 1 {
		t.Fatalf("expected 1 score, got %d", len(csafVuln.Scores))
	}
	if csafVuln.Scores[0].CVSSV3.BaseScore != 8.5 {
		t.Fatalf("expected base score 8.5, got %f", csafVuln.Scores[0].CVSSV3.BaseScore)
	}
}

func TestBuildVulnerability_WithoutFeed(t *testing.T) {
	orgID := testOrgID()
	cvss := 5.0
	vuln := models.Vulnerability{
		ID:           uuid.New(),
		OrgID:        orgID,
		Cve:          "CVE-2024-4000",
		CvssScore:    &cvss,
		Severity:     "medium",
		EuvdID:       "EUVD-VULN-ONLY",
		DiscoveredAt: time.Date(2024, 7, 1, 0, 0, 0, 0, time.UTC),
	}

	feedMap := map[string]*models.VulnerabilityFeed{}

	doc := buildCSAFDocumentForTest(orgID, []models.Vulnerability{vuln}, feedMap)

	if len(doc.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(doc.Vulnerabilities))
	}

	csafVuln := doc.Vulnerabilities[0]

	if len(csafVuln.Threats) != 0 {
		t.Fatalf("expected 0 threats without feed and no exploitation, got %d", len(csafVuln.Threats))
	}

	hasVulnEuvdID := false
	for _, id := range csafVuln.IDs {
		if id.SystemName == "ENISA EUVD" && id.Text == "EUVD-VULN-ONLY" {
			hasVulnEuvdID = true
		}
	}
	if !hasVulnEuvdID {
		t.Fatal("expected EUVD ID from vuln model itself")
	}
}

func buildCSAFDocumentForTest(orgID uuid.UUID, vulns []models.Vulnerability, feedMap map[string]*models.VulnerabilityFeed) *CSAFDocument {
	g := &CSAFGenerator{}
	return g.buildCSAFDocument(context.Background(), orgID, vulns, feedMap)
}
