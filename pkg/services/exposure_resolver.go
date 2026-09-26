// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.

package services

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
	"github.com/vincents-ai/transparenz-server-oss/pkg/regulatory/cra"
)

// ExposureResolver assembles the product graph for a vulnerability and hands it
// to the regulatory resolver in pkg/regulatory/cra.
//
// It deliberately does not decide anything. The regulatory package returns an
// Assessment of scope and evidence; the caller's job — a human's job — is to
// turn that into a reportability determination.
type ExposureResolver struct {
	db     *gorm.DB
	logger *zap.Logger
	clock  func() time.Time
}

// NewExposureResolver constructs an ExposureResolver. A nil clock uses the
// system clock.
func NewExposureResolver(db *gorm.DB, logger *zap.Logger) *ExposureResolver {
	return &ExposureResolver{db: db, logger: logger, clock: time.Now}
}

// exposureRow is the join of the four tables that carry the composition
// evidence: which vulnerability, which scan, which SBOM, and which component
// inside it.
type exposureRow struct {
	VulnerabilityID  uuid.UUID
	SBOMID           uuid.UUID
	SBOMFilename     string
	SHA256           string
	ComponentName    string
	ComponentVersion string
	ComponentType    string
	ComponentPURL    string
	MatchConfidence  string
	FeedSource       string
	ScanDate         time.Time
	SBOMCreatedAt    time.Time
}

// Resolve walks Vulnerability -> scan_vulnerabilities -> scans -> sbom_uploads
// for one vulnerability and returns the regulatory Assessment.
//
// The SBOM's content hash is carried on each exposure. It is what lets an
// authority be shown that a product really did contain the component on a given
// date, rather than taking the resolver's word for it — which is the entire
// basis of a "we did not ship it" answer.
func (r *ExposureResolver) Resolve(ctx context.Context, orgID, vulnID uuid.UUID) (cra.Assessment, error) {
	now := r.clock()

	vuln, err := r.loadVulnerability(ctx, orgID, vulnID)
	if err != nil {
		return cra.Assessment{}, err
	}

	rows, err := r.loadExposureRows(ctx, orgID, vulnID)
	if err != nil {
		return cra.Assessment{}, err
	}

	exposures, err := r.groupIntoExposures(ctx, orgID, vuln.Cve, rows)
	if err != nil {
		return cra.Assessment{}, err
	}

	// Existing CRA reports for this vulnerability, so a re-run flags what is
	// already covered rather than inviting a duplicate filing.
	existing, err := r.loadExistingReports(ctx, orgID, vuln.Cve)
	if err != nil {
		return cra.Assessment{}, err
	}

	in := cra.ExposureInput{
		OrgID:           orgID,
		VulnID:          vulnID,
		CVE:             vuln.Cve,
		EUVDID:          vuln.EuvdID,
		Exposures:       exposures,
		Signals:         exploitationSignals(vuln),
		CVSSBase:        vuln.CvssScore,
		Awareness:       awarenessFrom(vuln, now),
		ExistingReports: existing,
	}
	assessment, err := cra.ResolveExposure(in, now)
	if err != nil {
		return cra.Assessment{}, err
	}
	return assessment, nil
}

func (r *ExposureResolver) loadVulnerability(ctx context.Context, orgID, vulnID uuid.UUID) (models.Vulnerability, error) {
	var vuln models.Vulnerability
	err := r.db.WithContext(ctx).
		Where("org_id = ? AND id = ?", orgID, vulnID).
		First(&vuln).Error
	if err != nil {
		return vuln, fmt.Errorf("load vulnerability %s: %w", vulnID, err)
	}
	return vuln, nil
}

// loadExposureRows performs the graph walk in a single round trip.
//
// The join is on scan_vulnerabilities -> scans -> sbom_uploads, scoped to the
// org on both the vulnerability and the scan. Table names come from the models'
// TableName() methods so the query stays schema-agnostic across the
// shared-schema, schema-per-org and instance-per-org tenancy modes.
func (r *ExposureResolver) loadExposureRows(ctx context.Context, orgID, vulnID uuid.UUID) ([]exposureRow, error) {
	sv := (&models.ScanVulnerability{}).TableName()
	scan := (&models.Scan{}).TableName()
	su := (&models.SbomUpload{}).TableName()

	var rows []exposureRow
	err := r.db.WithContext(ctx).
		Table(sv+" AS sv").
		Select(`sv.vulnerability_id AS vulnerability_id,
			scan.sbom_id AS sbom_id,
			su.filename AS sbom_filename,
			su.sha256 AS sha256,
			sv.sbom_component_name AS component_name,
			sv.sbom_component_version AS component_version,
			sv.sbom_component_type AS component_type,
			sv.sbom_component_purl AS component_purl,
			sv.match_confidence AS match_confidence,
			sv.feed_source AS feed_source,
			scan.scan_date AS scan_date,
			su.created_at AS sbom_created_at`).
		Joins("JOIN "+scan+" AS scan ON scan.id = sv.scan_id").
		Joins("JOIN "+su+" AS su ON su.id = scan.sbom_id").
		Where("sv.vulnerability_id = ? AND sv.org_id = ? AND scan.org_id = ?", vulnID, orgID, orgID).
		Order("scan.scan_date DESC").
		Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("walk exposure graph for vulnerability %s: %w", vulnID, err)
	}
	return rows, nil
}

// groupIntoExposures collapses repeated observations of the same
// (product, component, version) into one exposure carrying the most recent
// evidence.
//
// The same composition is observed by many scans across many SBOM revisions.
// Emitting one exposure per scan would bury the actual question — "which of
// our products ship this?" — under dozens of duplicates that each look like a
// separate finding, and would make the same product appear to need several
// separate reports.
func (r *ExposureResolver) groupIntoExposures(ctx context.Context, orgID uuid.UUID, cve string, rows []exposureRow) ([]cra.ProductExposure, error) {
	if len(rows) == 0 {
		return nil, nil
	}

	vexByProduct, err := r.loadVexClaims(ctx, orgID, cve)
	if err != nil {
		return nil, err
	}

	// The dedup key is the PRODUCT identity (the SBOM content hash), not the
	// upload id. Re-uploading the same SBOM produces a new row with a new uuid
	// and an identical hash; keying on the uuid would treat one product as
	// several and fragment the evidence for a single product into what looks
	// like several separate CRA questions.
	type key struct {
		productID string
		name      string
		version   string
		purl      string
	}
	byKey := map[key]*cra.ProductExposure{}
	order := make([]key, 0, len(rows))

	for _, row := range rows {
		productID := productIDFor(row)
		k := key{
			productID: productID,
			name:      row.ComponentName,
			version:   row.ComponentVersion,
			purl:      row.ComponentPURL,
		}
		e, seen := byKey[k]
		if !seen {
			e = &cra.ProductExposure{
				ProductID:        productID,
				ProductName:      productName(row),
				SbomID:           row.SBOMID,
				ComponentName:    row.ComponentName,
				ComponentVersion: row.ComponentVersion,
				ComponentPURL:    row.ComponentPURL,
				ComponentType:    row.ComponentType,
				// Reachability defaults to Unknown, never to Reachable. A
				// resolver that assumes reachability invents a fact; one that
				// assumes non-reachability silently under-reports. Nothing in
				// the current schema evidences reachability at all, so Unknown
				// is the only honest value and it is the value every exposure
				// will take until reachability analysis exists.
				Reachability:    cra.ReachabilityUnknown,
				MatchConfidence: row.MatchConfidence,
				LatestScanAt:    row.ScanDate,
				VexStatements:   vexByProduct[productID],
			}
			if e.LatestScanAt.IsZero() {
				e.LatestScanAt = row.SBOMCreatedAt
			}
			byKey[k] = e
			order = append(order, k)
			continue
		}
		// Keep the freshest observation of the same composition.
		if row.ScanDate.After(e.LatestScanAt) {
			e.LatestScanAt = row.ScanDate
			e.MatchConfidence = row.MatchConfidence
			e.SbomID = row.SBOMID
			e.ProductName = productName(row)
		}
	}

	out := make([]cra.ProductExposure, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	return out, nil
}

// loadVexClaims returns the org's VEX statements for a CVE, indexed by product.
//
// A statement with an empty product_id is attached to every exposure, because
// an unscoped claim is a claim about the CVE across the estate. That is how
// the existing schema behaves, since product_id defaults to ”.
func (r *ExposureResolver) loadVexClaims(ctx context.Context, orgID uuid.UUID, cve string) (map[string][]cra.VexClaim, error) {
	var stmts []models.VexStatement
	err := r.db.WithContext(ctx).
		Where("org_id = ? AND cve = ?", orgID, cve).
		Find(&stmts).Error
	if err != nil {
		return nil, fmt.Errorf("load VEX statements for %s: %w", cve, err)
	}

	out := map[string][]cra.VexClaim{}
	for _, s := range stmts {
		claim := cra.VexClaim{
			StatementID:     s.ID,
			Status:          s.Status,
			Justification:   s.Justification,
			ImpactStatement: s.ImpactStatement,
			Confidence:      s.Confidence,
			ValidUntil:      s.ValidUntil,
		}
		if s.ValidUntil != nil && !s.ValidUntil.After(r.clock()) {
			claim.Expired = true
		}
		if s.ProductID == "" {
			out[""] = append(out[""], claim)
			continue
		}
		out[s.ProductID] = append(out[s.ProductID], claim)
	}
	return out, nil
}

// loadExistingReports returns CRA report IDs already opened for a CVE.
//
// Returns an empty slice rather than an error when the reporting table is not
// present, so the resolver works against a deployment that has not yet run the
// reporting migration.
func (r *ExposureResolver) loadExistingReports(ctx context.Context, orgID uuid.UUID, cve string) ([]uuid.UUID, error) {
	// The reporting table is introduced by migration 000044 and is not present
	// in every deployment yet; a missing table is a deployment state, not a
	// resolver failure.
	if !r.db.WithContext(ctx).Migrator().HasTable("compliance.cra_reports") {
		return nil, nil
	}
	var ids []uuid.UUID
	err := r.db.WithContext(ctx).
		Table("compliance.cra_reports").
		Where("org_id = ? AND cve = ?", orgID, cve).
		Pluck("id", &ids).Error
	if err != nil {
		return nil, fmt.Errorf("load existing CRA reports for %s: %w", cve, err)
	}
	return ids, nil
}

// exploitationSignals derives evidence inputs from the vulnerability record.
//
// Every signal is a statement by a source, never a determination. The
// manufacturer's own evidence — an active_exploitation_confirmed flag with a
// recorded awareness and evidence reference — is the strongest form, and is
// the only one that anchors the Article 14 clock.
func exploitationSignals(vuln models.Vulnerability) []cra.ExploitationSignal {
	var out []cra.ExploitationSignal

	if vuln.ActiveExploitationConfirmed {
		ref := vuln.AwarenessEvidence
		if ref == "" {
			ref = "determination:" + vuln.AwarenessSource
		}
		observed := vuln.UpdatedAt
		if vuln.AwarenessAt != nil {
			observed = *vuln.AwarenessAt
		}
		out = append(out, cra.ExploitationSignal{
			Source:     cra.EvidenceSourceInternalTelemetry,
			Reference:  ref,
			ObservedAt: observed,
			Summary:    "manufacturer confirmed active exploitation",
			// A confirmed determination is a first-hand observation, which is
			// the strongest class of evidence short of corroboration.
			Corroborated: false,
		})
	}

	if vuln.ExploitedInWild && vuln.KevDateAdded != nil {
		out = append(out, cra.ExploitationSignal{
			Source:     cra.EvidenceSourceCISAKEV,
			Reference:  fmt.Sprintf("KEV:%s", vuln.Cve),
			ObservedAt: *vuln.KevDateAdded,
			Summary:    "listed as known exploited",
			// CISA's KEV is an assertion, not a first-hand observation, so it
			// is deliberately not marked corroborated. Marking a single feed
			// entry as corroborated would inflate every KEV hit to the top of
			// the queue and flatten the distinction between one feed and
			// several agreeing.
			Corroborated: false,
		})
	}

	if vuln.EuvdID != "" {
		out = append(out, cra.ExploitationSignal{
			Source:     cra.EvidenceSourceEUVD,
			Reference:  "EUVD:" + vuln.EuvdID,
			ObservedAt: vuln.UpdatedAt,
			Summary:    "recorded in the ENISA EUVD",
		})
	}
	return out
}

// awarenessFrom projects the vulnerability's awareness record onto the
// regulatory Awareness value.
func awarenessFrom(vuln models.Vulnerability, now time.Time) cra.Awareness {
	a := cra.Awareness{
		Source:     cra.AwarenessSource(vuln.AwarenessSource),
		Evidence:   vuln.AwarenessEvidence,
		RecordedAt: now,
		RecordedBy: vuln.AwarenessRecordedBy,
	}
	if vuln.AwarenessAt != nil {
		a.AwarenessAt = *vuln.AwarenessAt
	}
	if vuln.AwarenessRecordedAt != nil {
		a.RecordedAt = *vuln.AwarenessRecordedAt
	}
	return a
}

// productIDFor derives a stable product identity from the SBOM.
//
// There is no product table in the current schema — an SBOM upload stands in
// for a product. Using the SBOM id keeps the identity stable and joinable with
// VEX product_ids, and using the content hash lets two uploads of the same
// document collapse to one product.
func productIDFor(row exposureRow) string {
	if row.SHA256 != "" {
		return "sbom:" + row.SHA256
	}
	return "sbom:" + row.SBOMID.String()
}

func productName(row exposureRow) string {
	name := strings.TrimSpace(row.SBOMFilename)
	if name == "" {
		return "SBOM " + row.SBOMID.String()
	}
	return name
}
