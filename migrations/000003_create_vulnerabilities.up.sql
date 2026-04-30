CREATE TABLE compliance.vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES compliance.organizations(id) ON DELETE CASCADE,
    cve TEXT NOT NULL,
    cvss_score DECIMAL(3,1),
    severity TEXT CHECK (severity IN ('critical', 'high', 'medium', 'low', 'unknown')),
    
    -- EU CRA metadata
    exploited_in_wild BOOLEAN DEFAULT FALSE,
    kev_date_added TIMESTAMPTZ,
    euvd_id TEXT,
    bsi_tr_03116_compliant BOOLEAN,
    sovereign_feed_source TEXT,
    
    discovered_at TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    
    UNIQUE(org_id, cve)
);

CREATE INDEX idx_vulnerabilities_org_cve ON compliance.vulnerabilities(org_id, cve);
CREATE INDEX idx_vulnerabilities_org_severity ON compliance.vulnerabilities(org_id, severity);
CREATE INDEX idx_vulnerabilities_kev_date ON compliance.vulnerabilities(kev_date_added) WHERE kev_date_added IS NOT NULL;
