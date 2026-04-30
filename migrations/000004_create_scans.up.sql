CREATE TABLE compliance.scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES compliance.organizations(id) ON DELETE CASCADE,
    sbom_id UUID NOT NULL,
    scan_date TIMESTAMPTZ DEFAULT NOW(),
    scanner_version TEXT,
    vulnerabilities_found INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    
    UNIQUE(org_id, sbom_id, scan_date)
);

CREATE INDEX idx_scans_org_sbom ON compliance.scans(org_id, sbom_id);
CREATE INDEX idx_scans_org_date ON compliance.scans(org_id, scan_date);
