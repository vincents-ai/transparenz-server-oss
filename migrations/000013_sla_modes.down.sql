ALTER TABLE compliance.sla_tracking DROP CONSTRAINT IF EXISTS sla_tracking_status_check;
ALTER TABLE compliance.sla_tracking ADD CONSTRAINT sla_tracking_status_check CHECK (status IN ('pending', 'reported', 'violated'));
