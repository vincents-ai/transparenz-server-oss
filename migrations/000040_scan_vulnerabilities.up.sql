CREATE TABLE compliance.scan_vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES compliance.scans(id) ON DELETE CASCADE,
    vulnerability_id UUID REFERENCES compliance.vulnerabilities(id) ON DELETE CASCADE,
    sbom_component_name TEXT NOT NULL,
    sbom_component_version TEXT NOT NULL,
    sbom_component_type TEXT DEFAULT '',
    sbom_component_purl TEXT DEFAULT '',
    match_confidence TEXT NOT NULL DEFAULT 'unknown',
    feed_source TEXT NOT NULL DEFAULT '',
    matched_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT uq_scan_vuln UNIQUE(scan_id, vulnerability_id, sbom_component_name, sbom_component_version)
);

CREATE INDEX idx_scan_vulns_scan ON compliance.scan_vulnerabilities(scan_id);
CREATE INDEX idx_scan_vulns_vuln ON compliance.scan_vulnerabilities(vulnerability_id);
