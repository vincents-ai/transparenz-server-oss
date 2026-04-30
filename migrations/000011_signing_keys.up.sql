CREATE TABLE compliance.signing_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES compliance.organizations(id) ON DELETE CASCADE,
    public_key TEXT NOT NULL,
    key_algorithm TEXT NOT NULL DEFAULT 'ed25519',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);

CREATE INDEX idx_signing_keys_org ON compliance.signing_keys(org_id);
