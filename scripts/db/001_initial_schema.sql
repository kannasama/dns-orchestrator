-- 001_initial_schema.sql
-- Creates the complete schema for dns-orchestrator.
-- See ARCHITECTURE.md §5 for full documentation.

-- ── Enumerations ───────────────────────────────────────────────────────────

CREATE TYPE provider_type   AS ENUM ('powerdns', 'cloudflare', 'digitalocean');
CREATE TYPE variable_type   AS ENUM ('ipv4', 'ipv6', 'target', 'string');
CREATE TYPE variable_scope  AS ENUM ('global', 'zone');
CREATE TYPE user_role       AS ENUM ('admin', 'operator', 'viewer');
CREATE TYPE auth_method     AS ENUM ('local', 'oidc', 'saml', 'api_key');

-- ── Tables ─────────────────────────────────────────────────────────────────

-- Provider registry
CREATE TABLE providers (
  id              BIGSERIAL PRIMARY KEY,
  name            TEXT NOT NULL UNIQUE,
  type            provider_type NOT NULL,
  api_endpoint    TEXT NOT NULL,
  encrypted_token TEXT NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Split-horizon views
CREATE TABLE views (
  id          BIGSERIAL PRIMARY KEY,
  name        TEXT NOT NULL UNIQUE,
  description TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- View ↔ Provider mapping (M:N)
CREATE TABLE view_providers (
  view_id     BIGINT NOT NULL REFERENCES views(id) ON DELETE CASCADE,
  provider_id BIGINT NOT NULL REFERENCES providers(id) ON DELETE CASCADE,
  PRIMARY KEY (view_id, provider_id)
);

-- DNS zones
CREATE TABLE zones (
  id                   BIGSERIAL PRIMARY KEY,
  name                 TEXT NOT NULL,
  view_id              BIGINT NOT NULL REFERENCES views(id) ON DELETE RESTRICT,
  deployment_retention INTEGER,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (name, view_id)
);

-- Variable registry
CREATE TABLE variables (
  id         BIGSERIAL PRIMARY KEY,
  name       TEXT NOT NULL,
  value      TEXT NOT NULL,
  type       variable_type NOT NULL,
  scope      variable_scope NOT NULL DEFAULT 'global',
  zone_id    BIGINT REFERENCES zones(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (name, zone_id),
  CHECK (scope = 'global' AND zone_id IS NULL
      OR scope = 'zone'   AND zone_id IS NOT NULL)
);

-- Users
CREATE TABLE users (
  id            BIGSERIAL PRIMARY KEY,
  username      TEXT NOT NULL UNIQUE,
  email         TEXT UNIQUE,
  password_hash TEXT,
  oidc_sub      TEXT UNIQUE,
  saml_name_id  TEXT UNIQUE,
  auth_method   auth_method NOT NULL DEFAULT 'local',
  is_active     BOOLEAN NOT NULL DEFAULT TRUE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Groups
CREATE TABLE groups (
  id          BIGSERIAL PRIMARY KEY,
  name        TEXT NOT NULL UNIQUE,
  role        user_role NOT NULL,
  description TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- User ↔ Group membership (M:N)
CREATE TABLE group_members (
  user_id  BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  group_id BIGINT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  PRIMARY KEY (user_id, group_id)
);

-- Audit log (append-only)
CREATE TABLE audit_log (
  id            BIGSERIAL PRIMARY KEY,
  entity_type   TEXT NOT NULL,
  entity_id     BIGINT,
  operation     TEXT NOT NULL,
  old_value     JSONB,
  new_value     JSONB,
  variable_used TEXT,
  identity      TEXT NOT NULL,
  auth_method   auth_method,
  ip_address    INET,
  timestamp     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- DNS records (stores raw templates with {{var}} placeholders)
CREATE TABLE records (
  id             BIGSERIAL PRIMARY KEY,
  zone_id        BIGINT NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
  name           TEXT NOT NULL,
  type           TEXT NOT NULL,
  ttl            INTEGER NOT NULL DEFAULT 300,
  value_template TEXT NOT NULL,
  priority       INTEGER NOT NULL DEFAULT 0,
  last_audit_id  BIGINT REFERENCES audit_log(id),
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Deployment history
CREATE TABLE deployments (
  id           BIGSERIAL PRIMARY KEY,
  zone_id      BIGINT NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
  deployed_by  BIGINT NOT NULL REFERENCES users(id),
  deployed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  seq          BIGINT NOT NULL,
  snapshot     JSONB NOT NULL
);

-- Active sessions
CREATE TABLE sessions (
  id                   BIGSERIAL PRIMARY KEY,
  user_id              BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash           TEXT NOT NULL UNIQUE,
  expires_at           TIMESTAMPTZ NOT NULL,
  absolute_expires_at  TIMESTAMPTZ NOT NULL,
  last_seen_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- API keys
CREATE TABLE api_keys (
  id           BIGSERIAL PRIMARY KEY,
  user_id      BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  key_hash     TEXT NOT NULL UNIQUE,
  description  TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at   TIMESTAMPTZ,
  revoked      BOOLEAN NOT NULL DEFAULT FALSE,
  delete_after TIMESTAMPTZ
);
