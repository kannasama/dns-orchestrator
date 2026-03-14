-- Workstream 5: Multi-repo GitOps — git repository configuration

CREATE TABLE git_repos (
  id                    SERIAL PRIMARY KEY,
  name                  VARCHAR(100) UNIQUE NOT NULL,
  remote_url            TEXT NOT NULL,
  auth_type             VARCHAR(10) NOT NULL DEFAULT 'none'
                        CHECK (auth_type IN ('ssh', 'https', 'none')),
  encrypted_credentials TEXT,
  default_branch        VARCHAR(100) NOT NULL DEFAULT 'main',
  local_path            TEXT,
  known_hosts           TEXT,
  is_enabled            BOOLEAN NOT NULL DEFAULT true,
  last_sync_at          TIMESTAMPTZ,
  last_sync_status      VARCHAR(20),
  last_sync_error       TEXT,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_git_repos_enabled ON git_repos (is_enabled) WHERE is_enabled = true;

-- Add git repo reference and branch override to zones
ALTER TABLE zones ADD COLUMN git_repo_id INTEGER REFERENCES git_repos(id) ON DELETE SET NULL;
ALTER TABLE zones ADD COLUMN git_branch VARCHAR(100);
