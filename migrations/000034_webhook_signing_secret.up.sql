ALTER TABLE compliance.greenbone_webhooks ADD COLUMN signing_secret TEXT DEFAULT '';
ALTER TABLE compliance.sbom_webhooks ADD COLUMN signing_secret TEXT DEFAULT '';
