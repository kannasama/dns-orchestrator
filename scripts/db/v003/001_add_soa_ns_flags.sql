-- 001_add_soa_ns_flags.sql
-- Adds SOA/NS drift control flags to zones table.

ALTER TABLE zones ADD COLUMN manage_soa BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE zones ADD COLUMN manage_ns  BOOLEAN NOT NULL DEFAULT FALSE;
