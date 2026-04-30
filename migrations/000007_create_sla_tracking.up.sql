CREATE TABLE compliance.sla_tracking (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES compliance.organizations(id) ON DELETE CASCADE,
    cve TEXT NOT NULL,
    sbom_id UUID,  -- NULL for per_cve mode, populated for per_sbom mode
    deadline TIMESTAMPTZ NOT NULL,
    status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'reported', 'violated')),
    notified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    
    UNIQUE(org_id, cve, sbom_id)
);

CREATE INDEX idx_sla_tracking_org_status ON compliance.sla_tracking(org_id, status);
CREATE INDEX idx_sla_tracking_org_deadline ON compliance.sla_tracking(org_id, deadline);
