-- NIS2 competent-authority routing metadata.
-- member_state: ISO 3166-1 alpha-2 EU member-state code used to select the
-- national CSIRT / competent authority when no explicit endpoint override is
-- configured.
-- sector/entity_class: captured for authority routing and payload context.
ALTER TABLE compliance.organizations
    ADD COLUMN IF NOT EXISTS nis2_member_state TEXT,
    ADD COLUMN IF NOT EXISTS nis2_sector TEXT,
    ADD COLUMN IF NOT EXISTS nis2_entity_class TEXT;

ALTER TABLE compliance.organizations
    ADD CONSTRAINT organizations_nis2_member_state_format
        CHECK (nis2_member_state IS NULL OR nis2_member_state ~ '^[A-Z]{2}$'),
    ADD CONSTRAINT organizations_nis2_entity_class_check
        CHECK (nis2_entity_class IS NULL OR nis2_entity_class IN ('essential', 'important'));

CREATE INDEX IF NOT EXISTS idx_organizations_nis2_member_state
    ON compliance.organizations(nis2_member_state)
    WHERE nis2_member_state IS NOT NULL;
