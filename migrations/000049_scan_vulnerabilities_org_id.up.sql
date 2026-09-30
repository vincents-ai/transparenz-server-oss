ALTER TABLE compliance.scan_vulnerabilities
    ADD COLUMN org_id UUID;

UPDATE compliance.scan_vulnerabilities AS sv
SET org_id = s.org_id
FROM compliance.scans AS s
WHERE s.id = sv.scan_id;

ALTER TABLE compliance.scan_vulnerabilities
    ALTER COLUMN org_id SET NOT NULL;

ALTER TABLE compliance.scan_vulnerabilities
    ADD CONSTRAINT scan_vulnerabilities_org_id_fkey
    FOREIGN KEY (org_id) REFERENCES compliance.organizations(id) ON DELETE CASCADE;

ALTER TABLE compliance.scan_vulnerabilities
    DROP CONSTRAINT uq_scan_vuln;

ALTER TABLE compliance.scan_vulnerabilities
    ADD CONSTRAINT uq_scan_vuln
    UNIQUE (scan_id, vulnerability_id, sbom_component_name, sbom_component_version, org_id);

CREATE INDEX idx_scan_vulns_org
    ON compliance.scan_vulnerabilities(org_id);
