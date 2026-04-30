CREATE TABLE compliance.grc_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES compliance.organizations(id) ON DELETE CASCADE,
    vulnerability_id UUID REFERENCES compliance.vulnerabilities(id) ON DELETE SET NULL,
    control_id VARCHAR(255) NOT NULL,
    framework VARCHAR(255) NOT NULL,
    mapping_type VARCHAR(50) NOT NULL,
    confidence DECIMAL(5,4) NOT NULL DEFAULT 0.0,
    evidence TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_grc_mappings_unique ON compliance.grc_mappings(org_id, COALESCE(vulnerability_id, '00000000-0000-0000-0000-000000000000'::uuid), control_id);

CREATE INDEX idx_grc_mappings_org_id ON compliance.grc_mappings(org_id);
CREATE INDEX idx_grc_mappings_vulnerability_id ON compliance.grc_mappings(vulnerability_id);
CREATE INDEX idx_grc_mappings_framework ON compliance.grc_mappings(framework);
