ALTER TABLE compliance.cra_reports
    DROP CONSTRAINT IF EXISTS cra_reports_product_version_len,
    DROP CONSTRAINT IF EXISTS cra_reports_manufacturer_name_len;

ALTER TABLE compliance.cra_reports
    DROP COLUMN IF EXISTS member_states,
    DROP COLUMN IF EXISTS product_version,
    DROP COLUMN IF EXISTS manufacturer_name;
