CREATE TABLE compliance.vex_publications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vex_id UUID NOT NULL REFERENCES compliance.vex_statements(id) ON DELETE CASCADE,
    published_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    channel TEXT NOT NULL CHECK (channel IN ('csaf_trusted_provider', 'url', 'file')),
    response JSONB,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'published', 'failed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_vex_publications_vex ON compliance.vex_publications(vex_id);
CREATE INDEX idx_vex_publications_status ON compliance.vex_publications(status);
