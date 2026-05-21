// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package services

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
)

var (
	mockPkgNames = []string{
		"openssl", "libcurl", "nginx", "postgresql", "redis",
		"nodejs", "python3", "glibc", "libxml2", "sqlite3",
		"zlib", "libpng", "libjpeg", "freetype", "harfbuzz",
		"expat", "libtasn1", "p11-kit", "gmp", "nettle",
		"gnutls", "krb5", "cyrus-sasl", "openldap", "mariadb",
		"httpd", "tomcat", "spring-core", "log4j", "jackson-databind",
		"guava", "commons-io", "commons-lang3", "snakeyaml", "junit",
		"docker", "containerd", "runc", "kubectl", "etcd",
		"coredns", "flannel", "calico", "istio", "envoy",
	}

	mockVersions = []string{
		"1.1.1", "1.1.1a", "1.1.1b", "1.1.1c", "1.1.1d",
		"2.0.0", "2.1.0", "2.2.0", "2.3.0", "2.4.0",
		"3.0.0", "3.1.0", "3.2.0", "3.3.0", "3.4.0",
		"4.0.0", "4.1.0", "4.2.0", "4.3.0", "4.4.0",
		"5.0.0", "5.1.0", "5.2.0", "5.3.0", "5.4.0",
		"8.0.0", "8.1.0", "8.2.0", "9.0.0", "9.1.0",
	}

	mockSeverities = []string{"Critical", "High", "Medium", "Low"}
)

func generateMockFeeds(count int) []models.VulnerabilityFeed {
	rng := rand.New(rand.NewSource(42))
	feeds := make([]models.VulnerabilityFeed, count)

	for i := 0; i < count; i++ {
		pkgName := mockPkgNames[rng.Intn(len(mockPkgNames))]
		version := mockVersions[rng.Intn(len(mockVersions))]
		severity := mockSeverities[rng.Intn(len(mockSeverities))]

		affectedProducts := generateAffectedProducts(rng, pkgName, version)
		apJSON, _ := json.Marshal(affectedProducts)

		feeds[i] = models.VulnerabilityFeed{
			ID:               uuid.New(),
			Cve:              fmt.Sprintf("CVE-2024-%05d", i+1),
			KevExploited:     rng.Float64() < 0.05,
			EnisaEuvdID:      fmt.Sprintf("EUVDID-%d", i),
			EnisaSeverity:    severity,
			BsiAdvisoryID:    fmt.Sprintf("BSI-%d", i),
			AffectedProducts: apJSON,
			LastSyncedAt:     time.Now(),
			CreatedAt:        time.Now(),
			UpdatedAt:        time.Now(),
		}
	}

	return feeds
}

func generateAffectedProducts(rng *rand.Rand, pkgName, version string) []affectedProduct {
	numProducts := 1 + rng.Intn(3)
	products := make([]affectedProduct, numProducts)

	for j := 0; products[0].Name == ""; j++ {
		products[0] = affectedProduct{
			Name:    pkgName,
			Vendor:  "vendor-" + pkgName,
			Version: version,
		}
	}

	for j := 1; j < numProducts; j++ {
		switch rng.Intn(3) {
		case 0:
			products[j] = affectedProduct{
				Name:    pkgName + "-lib",
				Vendor:  "vendor-" + pkgName,
				Version: version,
			}
		case 1:
			products[j] = affectedProduct{
				Name:    pkgName,
				Vendor:  "alt-vendor",
				Version: mockVersions[rng.Intn(len(mockVersions))],
			}
		case 2:
			products[j] = affectedProduct{
				Name:    pkgName + "-core",
				Vendor:  "vendor-" + pkgName,
				Version: version,
			}
		}
	}

	return products
}

func generateMockComponents(count int) []SBOMComponent {
	rng := rand.New(rand.NewSource(99))
	components := make([]SBOMComponent, count)

	for i := 0; i < count; i++ {
		pkgName := mockPkgNames[rng.Intn(len(mockPkgNames))]
		components[i] = SBOMComponent{
			Name:    pkgName,
			Version: mockVersions[rng.Intn(len(mockVersions))],
			Type:    "library",
			PURL:    fmt.Sprintf("pkg:generic/%s@%s", pkgName, mockVersions[rng.Intn(len(mockVersions))]),
			Group:   "",
		}
	}

	return components
}

func BenchmarkMatchIndex_Build_50K(b *testing.B) {
	feeds := generateMockFeeds(50000)
	idx := NewMatchIndex(5 * time.Minute)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := idx.Build(context.Background(), feeds); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMatchIndex_Lookup_1(b *testing.B) {
	feeds := generateMockFeeds(50000)
	idx := NewMatchIndex(5 * time.Minute)
	if err := idx.Build(context.Background(), feeds); err != nil {
		b.Fatal(err)
	}

	components := generateMockComponents(1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, comp := range components {
			_ = idx.Lookup(comp.Name, comp.Version)
		}
	}
}

func BenchmarkMatchIndex_Lookup_10(b *testing.B) {
	feeds := generateMockFeeds(50000)
	idx := NewMatchIndex(5 * time.Minute)
	if err := idx.Build(context.Background(), feeds); err != nil {
		b.Fatal(err)
	}

	components := generateMockComponents(10)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, comp := range components {
			_ = idx.Lookup(comp.Name, comp.Version)
		}
	}
}

func BenchmarkMatchIndex_Lookup_100(b *testing.B) {
	feeds := generateMockFeeds(50000)
	idx := NewMatchIndex(5 * time.Minute)
	if err := idx.Build(context.Background(), feeds); err != nil {
		b.Fatal(err)
	}

	components := generateMockComponents(100)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, comp := range components {
			_ = idx.Lookup(comp.Name, comp.Version)
		}
	}
}

func BenchmarkMatchIndex_Lookup_500(b *testing.B) {
	feeds := generateMockFeeds(50000)
	idx := NewMatchIndex(5 * time.Minute)
	if err := idx.Build(context.Background(), feeds); err != nil {
		b.Fatal(err)
	}

	components := generateMockComponents(500)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, comp := range components {
			_ = idx.Lookup(comp.Name, comp.Version)
		}
	}
}
