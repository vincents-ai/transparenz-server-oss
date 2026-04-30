ALTER TABLE compliance.scans DROP CONSTRAINT IF EXISTS scans_sbom_id_fkey;
ALTER TABLE compliance.sla_tracking DROP CONSTRAINT IF EXISTS sla_tracking_sbom_id_fkey;
