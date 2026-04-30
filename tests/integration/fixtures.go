//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// CycloneDX SBOM generators
// ---------------------------------------------------------------------------

// GenerateVulnerableCycloneDXSBOM creates a CycloneDX SBOM with a known-vulnerable component.
func GenerateVulnerableCycloneDXSBOM(t *testing.T) []byte {
	t.Helper()
	return MustGenerateCycloneDXSBOM("vulnerable-app", "1.0.0", []CycloneDXComponent{
		{Name: "nginx", Version: "1.25.4", PURL: "pkg:generic/nginx@1.25.4"},
	})
}

// GenerateSafeCycloneDXSBOM creates a CycloneDX SBOM with a safe component.
func GenerateSafeCycloneDXSBOM(t *testing.T) []byte {
	t.Helper()
	return MustGenerateCycloneDXSBOM("safe-app", "1.0.0", []CycloneDXComponent{
		{Name: "nginx", Version: "1.25.3", PURL: "pkg:generic/nginx@1.25.3"},
	})
}

// GenerateMultiComponentCycloneDXSBOM creates a CycloneDX SBOM with multiple components.
func GenerateMultiComponentCycloneDXSBOM(t *testing.T) []byte {
	t.Helper()
	return MustGenerateCycloneDXSBOM("multi-app", "2.0.0", []CycloneDXComponent{
		{Name: "nginx", Version: "1.25.4", PURL: "pkg:generic/nginx@1.25.4"},
		{Name: "openssl", Version: "1.1.1k", PURL: "pkg:generic/openssl@1.1.1k"},
		{Name: "log4j-core", Version: "2.14.1", PURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
		{Name: "spring-boot", Version: "2.6.0", PURL: "pkg:maven/org.springframework.boot/spring-boot@2.6.0"},
		{Name: "jquery", Version: "3.6.0", PURL: "pkg:npm/jquery@3.6.0"},
	})
}

// GenerateLargeCycloneDXSBOM creates a CycloneDX SBOM with many components.
func GenerateLargeCycloneDXSBOM(t *testing.T, count int) []byte {
	t.Helper()
	unique := uuid.New().String()[:8]
	components := make([]CycloneDXComponent, count)
	for i := 0; i < count; i++ {
		components[i] = CycloneDXComponent{
			Name:    fmt.Sprintf("component-%s-%d", unique, i),
			Version: "1.0.0",
			PURL:    fmt.Sprintf("pkg:generic/component-%s-%d@1.0.0", unique, i),
		}
	}
	return MustGenerateCycloneDXSBOM("large-app-"+unique, "3.0.0", components)
}

// GenerateEmptyCycloneDXSBOM creates a valid CycloneDX SBOM with no components.
func GenerateEmptyCycloneDXSBOM(t *testing.T) []byte {
	t.Helper()
	return MustGenerateCycloneDXSBOM("empty-app", "1.0.0", nil)
}

// GenerateCycloneDXWithSpecificCVEs creates a CycloneDX SBOM with components known to have specific CVEs.
func GenerateCycloneDXWithSpecificCVEs(t *testing.T) []byte {
	t.Helper()
	return MustGenerateCycloneDXSBOM("cve-targeted-app", "1.0.0", []CycloneDXComponent{
		// Log4Shell - CVE-2021-44228
		{Name: "log4j-core", Version: "2.14.1", PURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
		// Heartbleed - CVE-2014-0160
		{Name: "openssl", Version: "1.0.1f", PURL: "pkg:generic/openssl@1.0.1f"},
	})
}

type CycloneDXComponent struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
	PURL    string `json:"purl,omitempty"`
}

func MustGenerateCycloneDXSBOM(appName, appVersion string, components []CycloneDXComponent) []byte {
	comps := make([]interface{}, len(components))
	for i, c := range components {
		comp := map[string]interface{}{
			"name":    c.Name,
			"version": c.Version,
			"type":    "library",
		}
		if c.PURL != "" {
			comp["purl"] = c.PURL
		}
		comps[i] = comp
	}

	sbom := map[string]interface{}{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"metadata": map[string]interface{}{
			"component": map[string]interface{}{
				"name":    appName,
				"version": appVersion,
				"type":    "application",
			},
		},
	}
	if len(comps) > 0 {
		sbom["components"] = comps
	} else {
		sbom["components"] = []interface{}{}
	}

	data, err := json.Marshal(sbom)
	if err != nil {
		panic(fmt.Sprintf("failed to marshal CycloneDX SBOM: %v", err))
	}
	return data
}

// ---------------------------------------------------------------------------
// SPDX SBOM generators
// ---------------------------------------------------------------------------

// GenerateSPDXSBOM creates a minimal SPDX 2.3 SBOM.
func GenerateSPDXSBOM(t *testing.T) []byte {
	t.Helper()
	sbom := map[string]interface{}{
		"spdxVersion":   "SPDX-2.3",
		"dataLicense":   "CC0-1.0",
		"SPDXID":        "SPDXRef-DOCUMENT",
		"name":          "test-app",
		"documentNamespace": "https://example.com/test-app",
		"creationInfo": map[string]interface{}{
			"created":  time.Now().UTC().Format("2006-01-02T15:04:05Z"),
			"creators": []string{"Tool: integration-test"},
		},
		"packages": []interface{}{
			map[string]interface{}{
				"SPDXID":           "SPDXRef-Package-nginx",
				"name":             "nginx",
				"versionInfo":      "1.25.4",
				"downloadLocation": "https://nginx.org/download/nginx-1.25.4.tar.gz",
				"filesAnalyzed":    false,
			},
		},
	}

	data, err := json.Marshal(sbom)
	if err != nil {
		t.Fatalf("failed to marshal SPDX SBOM: %v", err)
	}
	return data
}

// ---------------------------------------------------------------------------
// Invalid / malformed SBOM generators
// ---------------------------------------------------------------------------

// GenerateMalformedJSON returns invalid JSON bytes.
func GenerateMalformedJSON() []byte {
	return []byte(`{this is not valid json!!!`)
}

// GenerateEmptyFile returns empty bytes.
func GenerateEmptyFile() []byte {
	return []byte{}
}

// GenerateNonJSONSBOM returns a plain text file.
func GenerateNonJSONSBOM() []byte {
	return []byte("This is not a JSON file at all, just plain text.\n")
}

// GenerateMissingFieldsCycloneDX returns CycloneDX JSON missing required fields.
func GenerateMissingFieldsCycloneDX() []byte {
	return []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5"}`)
}

// GenerateWrongFormatSBOM returns valid JSON but not a recognized SBOM format.
func GenerateWrongFormatSBOM() []byte {
	return []byte(`{"name":"test","version":"1.0","type":"unknown"}`)
}

// ---------------------------------------------------------------------------
// Random data generators
// ---------------------------------------------------------------------------

// RandomOrgName generates a unique organization name for testing.
func RandomOrgName() string {
	return fmt.Sprintf("Test Org %d", rand.Intn(100000))
}

// RandomEmail generates a unique email for testing.
func RandomEmail() string {
	return fmt.Sprintf("test-%d@example.com", rand.Intn(1000000))
}

// RandomAppName generates a unique app name for SBOM testing.
func RandomAppName() string {
	return fmt.Sprintf("test-app-%d", rand.Intn(100000))
}
