CREATE TABLE compliance.organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    
    -- Per-tenant configuration
    enisa_submission_mode TEXT DEFAULT 'export' CHECK (enisa_submission_mode IN ('api', 'csirt', 'export')),
    csaf_scope TEXT DEFAULT 'per_sbom' CHECK (csaf_scope IN ('per_cve', 'per_sbom', 'batch')),
    pdf_template TEXT DEFAULT 'generic' CHECK (pdf_template IN ('bsi_tr03116', 'generic', 'custom')),
    sla_tracking_mode TEXT DEFAULT 'per_cve' CHECK (sla_tracking_mode IN ('per_cve', 'per_sbom')),
    
    -- ENISA API credentials (encrypted)
    enisa_api_endpoint TEXT,
    enisa_api_key_encrypted TEXT,
    
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_organizations_slug ON compliance.organizations(slug);
