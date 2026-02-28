-- 002_add_indexes.sql
-- Performance indexes for dns-orchestrator.
-- See ARCHITECTURE.md §5.3 for full documentation.

CREATE INDEX idx_records_zone_id                ON records(zone_id);
CREATE UNIQUE INDEX idx_deployments_zone_seq     ON deployments(zone_id, seq);
CREATE INDEX idx_deployments_zone_id            ON deployments(zone_id);
CREATE INDEX idx_deployments_deployed_at        ON deployments(deployed_at DESC);
CREATE INDEX idx_variables_zone_id              ON variables(zone_id);
CREATE INDEX idx_audit_log_timestamp            ON audit_log(timestamp DESC);
CREATE INDEX idx_audit_log_entity               ON audit_log(entity_type, entity_id);
CREATE INDEX idx_sessions_user_id               ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at            ON sessions(expires_at);
CREATE INDEX idx_sessions_absolute_expires_at   ON sessions(absolute_expires_at);
CREATE INDEX idx_api_keys_key_hash              ON api_keys(key_hash);
CREATE INDEX idx_api_keys_user_id               ON api_keys(user_id);

-- Partial index: only indexes rows pending deletion; keeps the index small
CREATE INDEX idx_api_keys_delete_after          ON api_keys(delete_after)
  WHERE delete_after IS NOT NULL;
