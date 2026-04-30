ALTER TABLE compliance.organizations
    ADD COLUMN multi_tenant_mode TEXT DEFAULT 'shared'
        CHECK (multi_tenant_mode IN ('shared', 'schema_per_org', 'instance_per_org'));
