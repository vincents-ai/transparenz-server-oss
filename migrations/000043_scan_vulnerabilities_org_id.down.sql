DROP INDEX IF EXISTS compliance.idx_scan_vulns_org;

ALTER TABLE compliance.scan_vulnerabilities
    DROP CONSTRAINT IF EXISTS scan_vulnerabilities_org_id_fkey;

ALTER TABLE compliance.scan_vulnerabilities
    DROP CONSTRAINT uq_scan_vuln;

ALTER TABLE compliance.scan_vulnerabilities
    ADD CONSTRAINT uq_scan_vuln
    UNIQUE (scan_id, vulnerability_id, sbom_component_name, sbom_component_version);

ALTER TABLE compliance.scan_vulnerabilities
    DROP COLUMN org_id;
