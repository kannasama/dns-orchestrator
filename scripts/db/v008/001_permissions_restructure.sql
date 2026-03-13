-- Workstream 3: Permissions restructure — roles, role_permissions, group_members scoping

-- 1. Create roles table
CREATE TABLE roles (
  id          SERIAL PRIMARY KEY,
  name        VARCHAR(100) UNIQUE NOT NULL,
  description TEXT,
  is_system   BOOLEAN NOT NULL DEFAULT false,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 2. Create role_permissions table
CREATE TABLE role_permissions (
  role_id    INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  permission VARCHAR(100) NOT NULL,
  PRIMARY KEY (role_id, permission)
);

-- 3. Seed system roles
INSERT INTO roles (name, description, is_system) VALUES
  ('Admin', 'Full system access', true),
  ('Operator', 'Manage zones, records, deployments, and variables', true),
  ('Viewer', 'Read-only access with audit export', true);

-- 4. Seed Admin permissions (all permissions)
INSERT INTO role_permissions (role_id, permission)
SELECT r.id, p.perm
FROM roles r,
UNNEST(ARRAY[
  'zones.view', 'zones.create', 'zones.edit', 'zones.delete', 'zones.deploy', 'zones.rollback',
  'records.view', 'records.create', 'records.edit', 'records.delete', 'records.import',
  'providers.view', 'providers.create', 'providers.edit', 'providers.delete',
  'views.view', 'views.create', 'views.edit', 'views.delete',
  'variables.view', 'variables.create', 'variables.edit', 'variables.delete',
  'repos.view', 'repos.create', 'repos.edit', 'repos.delete',
  'audit.view', 'audit.export', 'audit.purge',
  'users.view', 'users.create', 'users.edit', 'users.delete',
  'groups.view', 'groups.create', 'groups.edit', 'groups.delete',
  'roles.view', 'roles.create', 'roles.edit', 'roles.delete',
  'settings.view', 'settings.edit',
  'backup.create', 'backup.restore'
]) AS p(perm)
WHERE r.name = 'Admin';

-- 5. Seed Operator permissions
INSERT INTO role_permissions (role_id, permission)
SELECT r.id, p.perm
FROM roles r,
UNNEST(ARRAY[
  'zones.view', 'zones.create', 'zones.edit', 'zones.delete', 'zones.deploy', 'zones.rollback',
  'records.view', 'records.create', 'records.edit', 'records.delete', 'records.import',
  'providers.view', 'providers.create', 'providers.edit', 'providers.delete',
  'views.view', 'views.create', 'views.edit', 'views.delete',
  'variables.view', 'variables.create', 'variables.edit', 'variables.delete',
  'repos.view', 'repos.create', 'repos.edit', 'repos.delete',
  'audit.view', 'audit.export',
  'groups.view',
  'roles.view'
]) AS p(perm)
WHERE r.name = 'Operator';

-- 6. Seed Viewer permissions
INSERT INTO role_permissions (role_id, permission)
SELECT r.id, p.perm
FROM roles r,
UNNEST(ARRAY[
  'zones.view',
  'records.view',
  'providers.view',
  'views.view',
  'variables.view',
  'repos.view',
  'audit.view', 'audit.export',
  'groups.view',
  'roles.view'
]) AS p(perm)
WHERE r.name = 'Viewer';

-- 7. Add role_id, scope_type, scope_id to group_members
ALTER TABLE group_members ADD COLUMN role_id INTEGER REFERENCES roles(id);
ALTER TABLE group_members ADD COLUMN scope_type VARCHAR(10);
ALTER TABLE group_members ADD COLUMN scope_id INTEGER;

-- 8. Migrate existing group_members: map each group's role to the corresponding system role
UPDATE group_members gm
SET role_id = r.id
FROM groups g
JOIN roles r ON LOWER(r.name) = g.role::text
WHERE gm.group_id = g.id;

-- 9. Make role_id NOT NULL now that all rows are populated
ALTER TABLE group_members ALTER COLUMN role_id SET NOT NULL;

-- 10. Drop the old role column from groups
ALTER TABLE groups DROP COLUMN role;

-- 11. Add index for permission resolution queries
CREATE INDEX idx_group_members_role_scope ON group_members (user_id, role_id, scope_type, scope_id);
CREATE INDEX idx_role_permissions_role_id ON role_permissions (role_id);

-- 12. Update the primary key on group_members to include role_id
-- A user can be in the same group with different roles at different scopes
ALTER TABLE group_members DROP CONSTRAINT group_members_pkey;
ALTER TABLE group_members ADD PRIMARY KEY (user_id, group_id, role_id);

-- 13. Add unique index with COALESCE to enforce scope uniqueness for nullable columns
-- (PostgreSQL PRIMARY KEY does not support expressions, but indexes do)
CREATE UNIQUE INDEX idx_group_members_unique_scope
  ON group_members (user_id, group_id, role_id, COALESCE(scope_type, ''), COALESCE(scope_id, 0));
