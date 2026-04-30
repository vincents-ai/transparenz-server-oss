CREATE TABLE compliance.enisa_submissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES compliance.organizations(id) ON DELETE CASCADE,
    submission_id TEXT UNIQUE,
    csaf_document JSONB NOT NULL,
    status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'submitted', 'acknowledged', 'failed')),
    submitted_at TIMESTAMPTZ,
    response JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_enisa_submissions_org_status ON compliance.enisa_submissions(org_id, status);
CREATE INDEX idx_enisa_submissions_org_date ON compliance.enisa_submissions(org_id, submitted_at);
