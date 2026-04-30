ALTER TABLE compliance.vex_publications DROP CONSTRAINT vex_publications_channel_check;
ALTER TABLE compliance.vex_publications ADD CONSTRAINT vex_publications_channel_check CHECK (channel IN ('csaf_trusted_provider', 'url', 'file', 'csaf', 'enisa'));
