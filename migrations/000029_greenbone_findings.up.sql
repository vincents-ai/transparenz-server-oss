CREATE TABLE compliance.greenbone_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES compliance.organizations(id) ON DELETE CASCADE,
    scan_id UUID NOT NULL REFERENCES compliance.scans(id) ON DELETE CASCADE,
    gvm_report_id VARCHAR(255) NOT NULL,
    gvm_result_id VARCHAR(255) NOT NULL,
    gvm_nvt_oid VARCHAR(255),
    cve VARCHAR(50),
    host VARCHAR(255) NOT NULL,
    port VARCHAR(50),
    severity DECIMAL(5,1),
    threat VARCHAR(50),
    name TEXT,
    description TEXT,
    qod INTEGER,
    vulnerability_id UUID REFERENCES compliance.vulnerabilities(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(org_id, gvm_result_id)
);

CREATE INDEX idx_greenbone_findings_org_id ON compliance.greenbone_findings(org_id);
CREATE INDEX idx_greenbone_findings_scan_id ON compliance.greenbone_findings(scan_id);
