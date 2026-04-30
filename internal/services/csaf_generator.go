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
	"time"

	"github.com/google/uuid"
	"github.com/transparenz/transparenz-server-oss/pkg/models"
	"github.com/transparenz/transparenz-server-oss/pkg/repository"
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

type ProductTree struct {
	FullNames []string  `json:"full_product_names,omitempty"`
	Product   []Product `json:"product,omitempty"`
	Branches  []Branch  `json:"branch,omitempty"`
}

type Product struct {
	Name       string `json:"name"`
	ProductID  string `json:"product_id"`
	Version    string `json:"version,omitempty"`
	VendorName string `json:"vendor_name,omitempty"`
}

type Branch struct {
	Name     string   `json:"name"`
	Category string   `json:"category"`
	Product  *Product `json:"product,omitempty"`
	Branches []Branch `json:"branch,omitempty"`
}

type CSAFVulnerability struct {
	CVE     string   `json:"cve"`
	Notes   []Note   `json:"notes,omitempty"`
	Threats []Threat `json:"threats,omitempty"`
	Scores  []Score  `json:"scores,omitempty"`
	IDs     []CSAFID `json:"ids,omitempty"`
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
	vulnRepo *repository.VulnerabilityRepository
	feedRepo *repository.VulnerabilityFeedRepository
	slaRepo  *repository.SlaTrackingRepository
	orgRepo  *repository.OrganizationRepository
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

	doc := g.buildCSAFDocument(orgID, []models.Vulnerability{*vuln}, feedMap)
	return doc, nil
}

func (g *CSAFGenerator) buildCSAFDocument(orgID uuid.UUID, vulns []models.Vulnerability, feedMap map[string]*models.VulnerabilityFeed) *CSAFDocument {
	doc := &CSAFDocument{}

	trackingID := uuid.New().String()
	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")

	doc.Distribution = Distribution{TLP: "WHITE"}

	doc.ProductTree = ProductTree{
		FullNames: []string{fmt.Sprintf("Transparenz Advisory %s", trackingID)},
	}

	doc.Document.Title = fmt.Sprintf("CSAF Report - Organization %s", orgID.String())
	doc.Document.Category = "csaf_2.0"
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

	g.appendSupportPeriodNotes(context.Background(), doc, orgID)

	for _, vuln := range vulns {
		var vulnFeed *models.VulnerabilityFeed
		if feedEntry, hasFeed := feedMap[vuln.Cve]; hasFeed {
			vulnFeed = feedEntry
		}
		csafVuln := g.buildVulnerability(vuln, vulnFeed)
		doc.Vulnerabilities = append(doc.Vulnerabilities, *csafVuln)
	}

	return doc
}

func (g *CSAFGenerator) buildVulnerability(vuln models.Vulnerability, feed *models.VulnerabilityFeed) *CSAFVulnerability {
	csafVuln := &CSAFVulnerability{
		CVE: vuln.Cve,
	}

	if vuln.CvssScore != nil {
		csafVuln.Scores = []Score{
			{
				Products: []string{"*"},
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

	return csafVuln
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
