CREATE TABLE compliance.org_telemetry_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES compliance.organizations(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL DEFAULT 'prometheus',
    otel_endpoint TEXT,
    otel_headers JSONB,
    metrics_token_hash TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_org_telemetry_org_id ON compliance.org_telemetry_configs(org_id);
