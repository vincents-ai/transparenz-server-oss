CREATE TABLE compliance.vex_statements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES compliance.organizations(id) ON DELETE CASCADE,
    cve TEXT NOT NULL,
    product_id TEXT NOT NULL DEFAULT '',
    justification TEXT NOT NULL CHECK (justification IN (
        'component_not_present',
        'vulnerable_code_not_present',
        'vulnerable_code_not_in_execute_path',
        'vulnerable_code_cannot_be_controlled_by_adversary',
        'inline_mitigations_already_exist'
    )),
    impact_statement TEXT DEFAULT '',
    confidence TEXT DEFAULT 'unknown' CHECK (confidence IN ('unknown', 'reasonable', 'high')),
    valid_until TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'pending_approval', 'active', 'expired', 'superseded')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_vex_statements_org ON compliance.vex_statements(org_id);
CREATE INDEX idx_vex_statements_cve ON compliance.vex_statements(cve);
CREATE INDEX idx_vex_statements_status ON compliance.vex_statements(status);
