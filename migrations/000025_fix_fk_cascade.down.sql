ALTER TABLE compliance.vulnerability_disclosures DROP CONSTRAINT IF EXISTS vulnerability_disclosures_org_id_fkey;
ALTER TABLE compliance.vulnerability_disclosures ADD CONSTRAINT vulnerability_disclosures_org_id_fkey FOREIGN KEY (org_id) REFERENCES compliance.organizations(id);
ALTER TABLE compliance.sbom_uploads DROP CONSTRAINT IF EXISTS sbom_uploads_org_id_fkey;
ALTER TABLE compliance.sbom_uploads ADD CONSTRAINT sbom_uploads_org_id_fkey FOREIGN KEY (org_id) REFERENCES compliance.organizations(id);
