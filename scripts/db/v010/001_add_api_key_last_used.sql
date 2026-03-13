-- Add last_used_at column to api_keys table
ALTER TABLE api_keys ADD COLUMN last_used_at TIMESTAMPTZ;
