CREATE TABLE compliance.greenbone_webhooks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES compliance.organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    secret_hash TEXT NOT NULL,
    actions JSONB NOT NULL DEFAULT '{"store_findings":true,"broadcast_alerts":true,"trigger_sla":true,"generate_csaf":true,"emit_otel":true,"severity_threshold":"medium"}',
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ
);

CREATE INDEX idx_greenbone_webhooks_org_id ON compliance.greenbone_webhooks(org_id);
