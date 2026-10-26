DROP TRIGGER IF EXISTS cra_srp_packages_no_update ON compliance.cra_srp_packages;
DROP FUNCTION IF EXISTS compliance.cra_srp_packages_append_only();

DROP INDEX IF EXISTS compliance.idx_cra_srp_packages_org;
DROP INDEX IF EXISTS compliance.idx_cra_srp_packages_report;

DROP TABLE IF EXISTS compliance.cra_srp_packages;
