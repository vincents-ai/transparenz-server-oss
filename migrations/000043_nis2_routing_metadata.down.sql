DROP INDEX IF EXISTS compliance.idx_organizations_nis2_member_state;

ALTER TABLE compliance.organizations
    DROP CONSTRAINT IF EXISTS organizations_nis2_entity_class_check,
    DROP CONSTRAINT IF EXISTS organizations_nis2_member_state_format;

ALTER TABLE compliance.organizations
    DROP COLUMN IF EXISTS nis2_entity_class,
    DROP COLUMN IF EXISTS nis2_sector,
    DROP COLUMN IF EXISTS nis2_member_state;
