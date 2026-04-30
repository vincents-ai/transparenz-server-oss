CREATE TABLE compliance.sbom_uploads (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES compliance.organizations(id),
    filename TEXT NOT NULL,
    format TEXT NOT NULL CHECK (format IN ('spdx-json', 'cyclonedx-json', 'spdx+xml', 'cyclonedx-xml')),
    size_bytes BIGINT NOT NULL,
    sha256 TEXT NOT NULL,
    document JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sbom_uploads_org_id ON compliance.sbom_uploads(org_id);
CREATE INDEX idx_sbom_uploads_sha256 ON compliance.sbom_uploads(sha256);
