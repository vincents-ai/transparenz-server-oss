// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package services

import (
	"context"
	jsonutil "github.com/vincents-ai/transparenz-server-oss/pkg/util/jsonutil"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/package-url/packageurl-go"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
	"github.com/vincents-ai/transparenz-server-oss/pkg/repository"
	"go.uber.org/zap"
)

type VulnzMatcher struct {
	feedRepo           *repository.VulnerabilityFeedRepository
	logger             *zap.Logger
	versionMatcher     *VersionMatcher
	matchIdx           *MatchIndex
	severityNormalizer *SeverityNormalizer
	indexTTL           time.Duration
}

func NewVulnzMatcher(feedRepo *repository.VulnerabilityFeedRepository, logger *zap.Logger) *VulnzMatcher {
	return &VulnzMatcher{
		feedRepo:           feedRepo,
		logger:             logger,
		versionMatcher:     NewVersionMatcher(),
		matchIdx:           NewMatchIndex(5 * time.Minute),
		severityNormalizer: NewSeverityNormalizer(),
		indexTTL:           5 * time.Minute,
	}
}

type VulnerabilityMatch struct {
	ID               uuid.UUID `json:"id"`
	CVE              string    `json:"cve"`
	CVSSScore        *float64  `json:"cvss_score,omitempty"`
	Severity         string    `json:"severity"`
	PackageName      string    `json:"package_name"`
	PackageVersion   string    `json:"package_version"`
	PackageType      string    `json:"package_type"`
	FixedVersion     string    `json:"fixed_version,omitempty"`
	VulnerabilityURL string    `json:"vulnerability_url"`
	ExploitedInWild  bool      `json:"exploited_in_wild,omitempty"`
	EUVDID           string    `json:"euvd_id,omitempty"`
	BSIAdvisoryID    string    `json:"bsi_advisory_id,omitempty"`
	Source           string    `json:"source"`
}

type SBOMComponent struct {
	Name    string
	Version string
	Type    string
	PURL    string
	Group   string
}

func (m *VulnzMatcher) MatchComponents(ctx context.Context, components []SBOMComponent) ([]VulnerabilityMatch, error) {
	feeds, err := m.feedRepo.List(ctx, 0, 0)
	if err != nil {
		return nil, err
	}

	if m.matchIdx.IsStale() {
		if buildErr := m.matchIdx.Build(ctx, feeds); buildErr != nil {
			m.logger.Warn("failed to build match index, using brute-force fallback", zap.Error(buildErr))
			return m.bruteForceMatch(feeds, components)
		}
	}

	var matches []VulnerabilityMatch
	// Keyed by vulnerability AND component, not by CVE alone.
	//
	// Keying on the CVE alone meant that when two distinct components were
	// affected by the same CVE, only the first produced a match and the second
	// silently vanished from the result. That is the worst possible failure
	// for exposure tracking: the report says the product is affected once, so
	// the reader concludes the second component is clean.
	//
	// A component can legitimately be reached through several lookup names
	// (its own name, and names derived from its PURL), so a CVE may be found
	// more than once for the SAME component. Deduplicating per component still
	// removes that redundancy, so multiple observations of one relationship
	// merge while genuinely distinct relationships both survive.
	seen := make(map[string]bool)

	for _, comp := range components {
		lookupNames := []string{comp.Name}
		if comp.PURL != "" {
			if p, err := packageurl.FromString(comp.PURL); err == nil && p.Name != "" {
				lookupNames = append(lookupNames, p.Name)
				if p.Namespace != "" {
					lookupNames = append(lookupNames, strings.ToLower(p.Namespace+"/"+p.Name))
				}
			}
		}

		for _, lookupName := range lookupNames {
			entries := m.matchIdx.Lookup(lookupName, comp.Version)
			for _, entry := range entries {
				if seen[exposureKey(entry.cve, comp)] {
					continue
				}
				seen[exposureKey(entry.cve, comp)] = true
				score, severityLabel := m.severityNormalizer.NormalizeMetadata(entry.baseScore, entry.severity, entry.bsiSeverity)
				match := VulnerabilityMatch{
					ID:               uuid.New(),
					CVE:              entry.cve,
					CVSSScore:        score,
					Severity:         severityLabel,
					PackageName:      comp.Name,
					PackageVersion:   comp.Version,
					PackageType:      comp.Type,
					VulnerabilityURL: "https://nvd.nist.gov/vuln/detail/" + entry.cve,
					ExploitedInWild:  entry.kevExploited,
					EUVDID:           entry.enisaEuvdID,
					BSIAdvisoryID:    entry.bsiAdvisoryID,
					Source:           entry.feedSource,
				}
				matches = append(matches, match)
			}
		}
	}

	return matches, nil
}

func (m *VulnzMatcher) bruteForceMatch(feeds []models.VulnerabilityFeed, components []SBOMComponent) ([]VulnerabilityMatch, error) {
	var matches []VulnerabilityMatch

	for _, comp := range components {
		for _, feed := range feeds {
			aps := parseAffectedProducts(feed.AffectedProducts)
			for _, ap := range aps {
				if m.matchComponent(comp, ap) {
					score, severityLabel := m.severityNormalizer.NormalizeMetadata(feed.BaseScore, feed.EnisaSeverity, feed.BsiSeverity)

					feedSource := "unknown"
					switch {
					case feed.BsiAdvisoryID != "":
						feedSource = "bsi"
					case feed.EnisaEuvdID != "":
						feedSource = "euvd"
					case feed.KevExploited:
						feedSource = "kev"
					}

					match := VulnerabilityMatch{
						ID:               uuid.New(),
						CVE:              feed.Cve,
						CVSSScore:        score,
						Severity:         severityLabel,
						PackageName:      comp.Name,
						PackageVersion:   comp.Version,
						PackageType:      comp.Type,
						VulnerabilityURL: "https://nvd.nist.gov/vuln/detail/" + feed.Cve,
						ExploitedInWild:  feed.KevExploited,
						EUVDID:           feed.EnisaEuvdID,
						BSIAdvisoryID:    feed.BsiAdvisoryID,
						Source:           feedSource,
					}
					matches = append(matches, match)
				}
			}
		}
	}

	return matches, nil
}

func (m *VulnzMatcher) matchComponent(comp SBOMComponent, ap affectedProduct) bool {
	compName := strings.ToLower(comp.Name)
	compVersion := strings.ToLower(comp.Version)
	apName := strings.ToLower(ap.Name)
	apVersion := strings.ToLower(ap.Version)

	shortLen := len(compName)
	longLen := len(apName)
	if len(compName) > len(apName) {
		shortLen = len(apName)
		longLen = len(compName)
	}
	nameMatch := longLen > 0 && float64(shortLen)/float64(longLen) >= 0.5 &&
		(strings.Contains(compName, apName) || strings.Contains(apName, compName))
	if !nameMatch {
		return false
	}

	result := m.versionMatcher.MatchVersion(compVersion, apVersion)
	return result == ExactMatch || result == RangeMatch || result == WildcardMatch
}

type affectedProduct struct {
	Name    string `json:"name"`
	Vendor  string `json:"vendor"`
	Version string `json:"version"`
}

// ParseSBOMComponents extracts component information from a CycloneDX or SPDX SBOM document.
// Exported for use by the commercial server's component extraction pipeline.
func ParseSBOMComponents(sbomDoc []byte) []SBOMComponent {
	var sbom map[string]interface{}
	if err := jsonutil.Unmarshal(sbomDoc, &sbom); err != nil {
		return nil
	}

	if componentsRaw, ok := sbom["components"].([]interface{}); ok {
		return parseCycloneDXComponents(componentsRaw)
	}

	if packagesRaw, ok := sbom["packages"].([]interface{}); ok {
		return parseSPDXComponents(packagesRaw)
	}

	return nil
}

func parseCycloneDXComponents(raw []interface{}) []SBOMComponent {
	var components []SBOMComponent
	for _, c := range raw {
		cm, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		comp := SBOMComponent{
			Name:    toString(cm["name"]),
			Version: toString(cm["version"]),
			Type:    toString(cm["type"]),
			PURL:    toString(cm["purl"]),
			Group:   toString(cm["group"]),
		}
		if comp.Name != "" {
			components = append(components, comp)
		}
	}
	return components
}

func parseSPDXComponents(raw []interface{}) []SBOMComponent {
	var components []SBOMComponent
	for _, p := range raw {
		pm, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		name := toString(pm["name"])
		if name == "" {
			name = toString(pm["SPDXID"])
		}
		comp := SBOMComponent{
			Name:    name,
			Version: toString(pm["versionInfo"]),
			Type:    "library",
			PURL:    extractSPDXPURL(pm),
		}
		if comp.Name != "" {
			components = append(components, comp)
		}
	}
	return components
}

func extractSPDXPURL(pkg map[string]interface{}) string {
	refs, ok := pkg["externalRefs"].([]interface{})
	if !ok {
		return ""
	}
	for _, r := range refs {
		rm, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		if toString(rm["referenceCategory"]) == "PACKAGE-MANAGER" {
			return toString(rm["referenceLocator"])
		}
	}
	return ""
}

func toString(v interface{}) string {
	if v == nil {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// exposureKey identifies one vulnerability-to-component relationship.
//
// A vulnerability alone is not a relationship: the same CVE can affect many
// components in one SBOM, and each of those is a separate exposure that must be
// reported, tracked and VEX'd independently. Version and type are included
// because two components sharing a name but differing in version or ecosystem
// are distinct products, and a fix shipped for one is not a fix for the other.
//
// The separator is a byte that cannot appear in a CVE or a package name, so no
// pair of distinct components can collide into one key.
func exposureKey(cve string, comp SBOMComponent) string {
	return cve + "\x00" + comp.Name + "\x00" + comp.Version + "\x00" + comp.Type
}
