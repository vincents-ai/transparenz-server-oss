// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
	"github.com/vincents-ai/transparenz-server-oss/pkg/repository"
)

type CSAFDocument struct {
	Document        Document            `json:"document"`
	Distribution    Distribution        `json:"distribution"`
	ProductTree     ProductTree         `json:"product_tree,omitempty"`
	Vulnerabilities []CSAFVulnerability `json:"vulnerabilities,omitempty"`
}

type Distribution struct {
	TLP    string `json:"tlp"`
	Legend string `json:"legend,omitempty"`
}

type Document struct {
	Title       string    `json:"title"`
	Category    string    `json:"category"`
	CSAFVersion string    `json:"csaf_version"`
	Publisher   Publisher `json:"publisher"`
	Tracking    Tracking  `json:"tracking"`
	Notes       []Note    `json:"notes,omitempty"`
}

type Publisher struct {
	Name     string `json:"name"`
	Category string `json:"category"`
}

type Tracking struct {
	ID                 string     `json:"id"`
	Status             string     `json:"status"`
	Version            string     `json:"version"`
	CurrentReleaseDate string     `json:"current_release_date"`
	InitialReleaseDate string     `json:"initial_release_date"`
	RevisionHistory    []Revision `json:"revision_history"`
	Generator          Generator  `json:"generator"`
}

type Revision struct {
	Number      string `json:"number"`
	Date        string `json:"date"`
	Description string `json:"description"`
}

type Generator struct {
	Engine string `json:"engine"`
	Date   string `json:"date"`
}

type Note struct {
	Text  string `json:"text"`
	Type  string `json:"type"`
	Title string `json:"title,omitempty"`
}

// ProductTree models the CSAF 2.0 product_tree. Affected products are listed
// once as full_product_names (each with a stable product_id) and referenced
// from each vulnerability's product_status.known_affected.
type ProductTree struct {
	Branches         []Branch          `json:"branches,omitempty"`
	FullProductNames []FullProductName `json:"full_product_names,omitempty"`
}

// FullProductName is a CSAF 2.0 full_product_name entry.
type FullProductName struct {
	ProductID                   string                      `json:"product_id"`
	Name                        string                      `json:"name"`
	ProductIdentificationHelper *ProductIdentificationHelper `json:"product_identification_helper,omitempty"`
}

// ProductIdentificationHelper carries identifiers (here the purl) that pin a
// product unambiguously. All sub-fields are optional per the CSAF 2.0 schema.
type ProductIdentificationHelper struct {
	PURL string `json:"purl,omitempty"`
}

type Branch struct {
	Name             string            `json:"name"`
	Category         string            `json:"category"`
	FullProductNames []FullProductName `json:"full_product_names,omitempty"`
	Branches         []Branch          `json:"branches,omitempty"`
}

type CSAFVulnerability struct {
	CVE           string         `json:"cve"`
	ProductStatus *ProductStatus `json:"product_status,omitempty"`
	Notes         []Note         `json:"notes,omitempty"`
	Threats       []Threat       `json:"threats,omitempty"`
	Scores        []Score        `json:"scores,omitempty"`
	IDs           []CSAFID       `json:"ids,omitempty"`
}

// ProductStatus states a product's status relative to the vulnerability.
// known_affected lists the product_ids that are affected (CSAF 2.0).
type ProductStatus struct {
	KnownAffected []string `json:"known_affected,omitempty"`
}

type Threat struct {
	Category string `json:"category"`
	Date     string `json:"date,omitempty"`
	Details  string `json:"details"`
}

type Score struct {
	Products []string    `json:"products"`
	CVSSV3   CVSSV3Score `json:"cvss_v3"`
}

type CVSSV3Score struct {
	BaseScore    float64 `json:"base_score"`
	BaseSeverity string  `json:"base_severity"`
	VectorString string  `json:"vector_string,omitempty"`
}

type CSAFID struct {
	SystemName string `json:"system_name"`
	Text       string `json:"text"`
}

type CSAFGenerator struct {
	vulnRepo     *repository.VulnerabilityRepository
	feedRepo     *repository.VulnerabilityFeedRepository
	slaRepo      *repository.SlaTrackingRepository
	orgRepo      *repository.OrganizationRepository
	scanVulnRepo *repository.ScanVulnerabilityRepository
}

func NewCSAFGeneratorWithOrg(
	vulnRepo *repository.VulnerabilityRepository,
	feedRepo *repository.VulnerabilityFeedRepository,
	slaRepo *repository.SlaTrackingRepository,
	orgRepo *repository.OrganizationRepository,
) *CSAFGenerator {
	return &CSAFGenerator{
		vulnRepo: vulnRepo,
		feedRepo: feedRepo,
		slaRepo:  slaRepo,
		orgRepo:  orgRepo,
	}
}

// WithScanVulnerabilityRepository wires the scan_vulnerability repository used
// to populate the CSAF product_tree and per-vulnerability product_status.
// Returns the receiver for chaining. Optional: when unset (or when a query
// fails / returns no rows), generated advisories omit product_status and keep
// the legacy wildcard CVSS product reference, so behaviour degrades gracefully.
// This is a separate setter rather than a constructor param to keep the
// constructor signature stable across module releases (the OSS module is
// consumed by downstream products via a version-pinned go.mod).
func (g *CSAFGenerator) WithScanVulnerabilityRepository(repo *repository.ScanVulnerabilityRepository) *CSAFGenerator {
	g.scanVulnRepo = repo
	return g
}

func (g *CSAFGenerator) GeneratePerCVE(ctx context.Context, orgID uuid.UUID, cve string) (*CSAFDocument, error) {
	vuln, err := g.vulnRepo.GetByCVE(ctx, cve)
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerability: %w", err)
	}

	feed, err := g.feedRepo.GetByCVE(ctx, cve)
	if err != nil && !errors.Is(err, repository.ErrVulnerabilityFeedNotFound) {
		return nil, fmt.Errorf("failed to get feed data: %w", err)
	}

	feedMap := map[string]*models.VulnerabilityFeed{}
	if feed != nil {
		feedMap[feed.Cve] = feed
	}

	doc := g.buildCSAFDocument(ctx, orgID, []models.Vulnerability{*vuln}, feedMap)
	return doc, nil
}

func (g *CSAFGenerator) buildCSAFDocument(ctx context.Context, orgID uuid.UUID, vulns []models.Vulnerability, feedMap map[string]*models.VulnerabilityFeed) *CSAFDocument {
	doc := &CSAFDocument{}

	trackingID := uuid.New().String()
	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")

	doc.Distribution = Distribution{TLP: "WHITE"}

	doc.Document.Title = fmt.Sprintf("CSAF Report - Organization %s", orgID.String())
	// CSAF 2.0 spec requires document.category to be one of the fixed enum values
	// (csaf_security_advisory, csaf_vex, csaf_security_incident_response,
	// csaf_informational_advisory, csaf_military_advisory). The literal "csaf_2.0"
	// is the *version*, not a valid category, and fails the official JSON schema.
	// This document is a CRA Art. 12 vulnerability report -> security advisory.
	doc.Document.Category = "csaf_security_advisory"
	doc.Document.CSAFVersion = "2.0"
	doc.Document.Publisher.Name = "Transparenz Server"
	doc.Document.Publisher.Category = "translator"
	doc.Document.Tracking = Tracking{
		ID:                 trackingID,
		Status:             "final",
		Version:            "1.0",
		CurrentReleaseDate: now,
		InitialReleaseDate: now,
		RevisionHistory:    []Revision{{Number: "1", Date: now, Description: "Initial advisory"}},
		Generator:          Generator{Engine: "transparenz-server", Date: now},
	}

	doc.Document.Notes = append(doc.Document.Notes, Note{
		Text:  "EU Cyber Resilience Act (CRA) Article 12 vulnerability report",
		Type:  "description",
		Title: "Compliance",
	})

	g.appendSupportPeriodNotes(ctx, doc, orgID)

	// Collect affected products across all vulnerabilities to populate the
	// CSAF 2.0 product_tree.full_product_names. Each vulnerability references
	// its affected products by product_id in product_status.known_affected.
	productIndex := make(map[string]FullProductName)
	for _, vuln := range vulns {
		var vulnFeed *models.VulnerabilityFeed
		if feedEntry, hasFeed := feedMap[vuln.Cve]; hasFeed {
			vulnFeed = feedEntry
		}
		csafVuln, affected := g.buildVulnerability(ctx, vuln, vulnFeed)
		for _, fpn := range affected {
			productIndex[fpn.ProductID] = fpn
		}
		doc.Vulnerabilities = append(doc.Vulnerabilities, *csafVuln)
	}

	if len(productIndex) > 0 {
		fullNames := make([]FullProductName, 0, len(productIndex))
		for _, fpn := range productIndex {
			fullNames = append(fullNames, fpn)
		}
		doc.ProductTree = ProductTree{FullProductNames: fullNames}
	}

	return doc
}

// buildVulnerability builds the CSAF vulnerability entry and returns it along
// with the affected products (for the product_tree). Affected products are
// sourced from scan_vulnerabilities, the join that links a CVE to the SBOM
// components (name/version/purl) it was matched against.
func (g *CSAFGenerator) buildVulnerability(ctx context.Context, vuln models.Vulnerability, feed *models.VulnerabilityFeed) (*CSAFVulnerability, []FullProductName) {
	csafVuln := &CSAFVulnerability{
		CVE: vuln.Cve,
	}

	affected := g.collectAffectedProducts(ctx, vuln.ID)
	if len(affected) > 0 {
		csafVuln.ProductStatus = &ProductStatus{KnownAffected: productIDs(affected)}
	}

	if vuln.CvssScore != nil {
		products := []string{"*"}
		if len(affected) > 0 {
			products = productIDs(affected)
		}
		csafVuln.Scores = []Score{
			{
				Products: products,
				CVSSV3: CVSSV3Score{
					BaseScore:    *vuln.CvssScore,
					BaseSeverity: vuln.Severity,
				},
			},
		}
	}

	if vuln.ExploitedInWild {
		dateStr := ""
		if vuln.KevDateAdded != nil {
			dateStr = vuln.KevDateAdded.Format(time.RFC3339)
		}
		csafVuln.Threats = append(csafVuln.Threats, Threat{
			Category: "exploit_status",
			Date:     dateStr,
			Details:  "Exploited in the Wild (CISA KEV)",
		})
	}

	if feed != nil && feed.KevExploited && !vuln.ExploitedInWild {
		dateStr := ""
		if feed.KevDateAdded != nil {
			dateStr = feed.KevDateAdded.Format(time.RFC3339)
		}
		csafVuln.Threats = append(csafVuln.Threats, Threat{
			Category: "exploit_status",
			Date:     dateStr,
			Details:  "Exploited in the Wild (CISA KEV)",
		})
	}

	notes := g.buildNotes(vuln, feed)
	csafVuln.Notes = notes

	if feed != nil {
		if feed.EnisaEuvdID != "" {
			csafVuln.IDs = append(csafVuln.IDs, CSAFID{
				SystemName: "ENISA EUVD",
				Text:       feed.EnisaEuvdID,
			})
		}
		if feed.BsiAdvisoryID != "" {
			csafVuln.IDs = append(csafVuln.IDs, CSAFID{
				SystemName: "BSI",
				Text:       feed.BsiAdvisoryID,
			})
		}
	}

	if vuln.EuvdID != "" {
		csafVuln.IDs = append(csafVuln.IDs, CSAFID{
			SystemName: "ENISA EUVD",
			Text:       vuln.EuvdID,
		})
	}

	return csafVuln, affected
}

// collectAffectedProducts queries scan_vulnerabilities for the components a
// vulnerability was matched against and maps them to CSAF FullProductName
// entries (deduped by product_id).
func (g *CSAFGenerator) collectAffectedProducts(ctx context.Context, vulnID uuid.UUID) []FullProductName {
	if g.scanVulnRepo == nil {
		return nil
	}
	records, err := g.scanVulnRepo.ListByVulnerabilityID(ctx, vulnID)
	if err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var products []FullProductName
	for _, rec := range records {
		fpn := scanRecordToProduct(rec)
		if seen[fpn.ProductID] {
			continue
		}
		seen[fpn.ProductID] = true
		products = append(products, fpn)
	}
	return products
}

// scanRecordToProduct maps a scan_vulnerability row to a CSAF FullProductName.
// The product_id is the purl when available (canonical and unique), otherwise a
// deterministic fallback derived from name and version.
func scanRecordToProduct(rec models.ScanVulnerability) FullProductName {
	name := rec.SbomComponentName
	version := rec.SbomComponentVersion
	displayName := name
	if version != "" {
		displayName = fmt.Sprintf("%s@%s", name, version)
	}
	productID := rec.SbomComponentPURL
	if productID == "" {
		productID = "CSAF_" + sanitizeProductID(name+"_"+version)
	}
	fpn := FullProductName{ProductID: productID, Name: displayName}
	if rec.SbomComponentPURL != "" {
		fpn.ProductIdentificationHelper = &ProductIdentificationHelper{PURL: rec.SbomComponentPURL}
	}
	return fpn
}

func productIDs(products []FullProductName) []string {
	ids := make([]string, len(products))
	for i, p := range products {
		ids[i] = p.ProductID
	}
	return ids
}

func sanitizeProductID(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'),
			(r >= '0' && r <= '9'),
			r == '_' || r == '-' || r == '.' || r == ':' || r == '/' || r == '@':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}

func (g *CSAFGenerator) buildNotes(vuln models.Vulnerability, feed *models.VulnerabilityFeed) []Note {
	var notes []Note

	notes = append(notes, Note{
		Text:  fmt.Sprintf("Severity: %s", vuln.Severity),
		Type:  "info",
		Title: "CVSS",
	})

	if vuln.CvssScore != nil {
		notes = append(notes, Note{
			Text:  fmt.Sprintf("CVSS v3 Base Score: %.1f", *vuln.CvssScore),
			Type:  "info",
			Title: "CVSS Score",
		})
	}

	if feed != nil && feed.EnisaSeverity != "" {
		notes = append(notes, Note{
			Text:  feed.EnisaSeverity,
			Type:  "info",
			Title: "ENISA Severity",
		})
	}

	if vuln.SovereignFeedSource != "" {
		notes = append(notes, Note{
			Text:  vuln.SovereignFeedSource,
			Type:  "info",
			Title: "Sovereign Feed Source",
		})
	}

	var bsiCompliant string
	if vuln.BsiTr03116Compliant != nil {
		if *vuln.BsiTr03116Compliant {
			bsiCompliant = "Yes"
		} else {
			bsiCompliant = "No"
		}
	} else if feed != nil && feed.BsiTr03116Compliant != nil {
		if *feed.BsiTr03116Compliant {
			bsiCompliant = "Yes"
		} else {
			bsiCompliant = "No"
		}
	}
	if bsiCompliant != "" {
		notes = append(notes, Note{
			Text:  bsiCompliant,
			Type:  "info",
			Title: "BSI TR-03116 Compliant",
		})
	}

	notes = append(notes, Note{
		Text:  "EU Cyber Resilience Act Article 12 disclosure report",
		Type:  "description",
		Title: "EU CRA",
	})

	notes = append(notes, Note{
		Text:  fmt.Sprintf("Discovered: %s", vuln.DiscoveredAt.Format(time.RFC3339)),
		Type:  "info",
		Title: "Discovery Time",
	})

	return notes
}

func (g *CSAFGenerator) appendSupportPeriodNotes(ctx context.Context, doc *CSAFDocument, orgID uuid.UUID) {
	if g.orgRepo == nil {
		return
	}
	status, err := g.orgRepo.GetSupportPeriodStatus(ctx, orgID)
	if err != nil {
		return
	}

	doc.Document.Notes = append(doc.Document.Notes, Note{
		Text:  fmt.Sprintf("CRA Article 13 Support Period: %d months declared", status.SupportPeriodMonths),
		Type:  "legal_disclaimer",
		Title: "Support Period",
	})

	if status.SupportStartDate != nil && status.SupportEndDate != nil {
		doc.Document.Notes = append(doc.Document.Notes, Note{
			Text: fmt.Sprintf(
				"Support coverage: %s to %s (%.1f%% elapsed)",
				status.SupportStartDate.Format(time.RFC3339),
				status.SupportEndDate.Format(time.RFC3339),
				status.PercentageElapsed,
			),
			Type:  "legal_disclaimer",
			Title: "Support Coverage",
		})
	}

	if status.IsExpired {
		doc.Document.Notes = append(doc.Document.Notes, Note{
			Text:  "WARNING: Support period has expired. CRA Article 13 obligations may not be met.",
			Type:  "legal_disclaimer",
			Title: "Support Period Status",
		})
	}
}
