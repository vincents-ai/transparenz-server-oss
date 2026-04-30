CREATE TABLE compliance.compliance_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES compliance.organizations(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL CHECK (event_type IN ('exploited_reported', 'sla_breach', 'enisa_submission', 'notification_sent')),
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    cve TEXT,
    reported_to_authority TEXT,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_compliance_events_org_type ON compliance.compliance_events(org_id, event_type);
CREATE INDEX idx_compliance_events_org_timestamp ON compliance.compliance_events(org_id, timestamp);
