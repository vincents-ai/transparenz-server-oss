ALTER TABLE compliance.scans ADD CONSTRAINT scans_sbom_id_fkey FOREIGN KEY (sbom_id) REFERENCES compliance.sbom_uploads(id) ON DELETE CASCADE;
ALTER TABLE compliance.sla_tracking ADD CONSTRAINT sla_tracking_sbom_id_fkey FOREIGN KEY (sbom_id) REFERENCES compliance.sbom_uploads(id) ON DELETE SET NULL;
