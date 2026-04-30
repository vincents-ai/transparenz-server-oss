ALTER TABLE compliance.organizations ADD COLUMN tier TEXT NOT NULL DEFAULT 'standard' CHECK (tier IN ('standard', 'enterprise', 'sovereign'));
ALTER TABLE compliance.organizations ADD COLUMN sla_mode TEXT NOT NULL DEFAULT 'alerts_only' CHECK (sla_mode IN ('alerts_only', 'approval_gate', 'fully_automatic'));
