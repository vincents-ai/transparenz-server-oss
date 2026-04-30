CREATE TABLE compliance.sbom_webhooks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES compliance.organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    secret_hash TEXT NOT NULL,
    actions JSONB NOT NULL DEFAULT '{"trigger_scan":true,"broadcast_alerts":true,"trigger_sla":true,"emit_otel":true}',
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ
);

CREATE INDEX idx_sbom_webhooks_org_id ON compliance.sbom_webhooks(org_id);
