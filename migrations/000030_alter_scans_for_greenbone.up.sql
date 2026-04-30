ALTER TABLE compliance.scans ADD COLUMN scanner_source VARCHAR(50) DEFAULT 'grype';
ALTER TABLE compliance.scans ADD COLUMN gvm_report_id VARCHAR(255);
