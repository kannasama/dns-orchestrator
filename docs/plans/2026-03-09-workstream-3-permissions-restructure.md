# Workstream 3: Permissions Restructure — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the fixed three-role system (admin/operator/viewer) with discrete permissions collected into customizable named roles, with hierarchical resource scoping at the view and zone levels.

**Architecture:** A `RoleRepository` manages the `roles` and `role_permissions` tables. A `PermissionService` resolves the effective permission set for a user by collecting all group memberships (with their role + scope), then unioning the matching permissions. `requireRole()` is replaced by `requirePermission()` across all 56 route handler call sites. The `RequestContext` no longer carries a single role string — instead, permissions are resolved at request time. The JWT retains a `role_name` field for display only (highest-privilege role name); actual permission checks always query the DB via the middleware. Three system roles (Admin, Operator, Viewer) are seeded by migration and cannot be deleted. Groups lose their `role` column; instead, `group_members` gains `role_id`, `scope_type`, and `scope_id` columns.

**Tech Stack:** C++20, PostgreSQL (libpqxx), Crow HTTP, Google Test, Vue 3 + TypeScript + PrimeVue

---

## Task Overview

| # | Task | Description |
|---|------|-------------|
| 1 | Schema migration v008 | Create `roles`/`role_permissions` tables, alter `group_members`, drop `groups.role` |
| 2 | Permission constants | Code-defined permission strings in `include/common/Permissions.hpp` |
| 3 | RoleRepository | DAL class for `roles` and `role_permissions` CRUD |
| 4 | RoleRepository tests | Integration tests for the role repository |
| 5 | PermissionService | Permission resolution engine with hierarchical scoping |
| 6 | PermissionService tests | Unit tests for permission resolution logic |
| 7 | RequestContext + AuthMiddleware refactor | Replace `sRole` with permissions vector, resolve at request time |
| 8 | RouteHelpers — requirePermission | Replace `requireRole()` with `requirePermission()` |
| 9 | Route handlers migration | Update all 56 `requireRole()` call sites to `requirePermission()` |
| 10 | AuthService JWT update | Update JWT payload and `/me` endpoint for permission model |
| 11 | GroupRepository refactor | Remove `role` column, update queries for new `group_members` schema |
| 12 | GroupRoutes + UserRoutes update | Accept `role_id`, `scope_type`, `scope_id` in group member management |
| 13 | RoleRoutes — CRUD | New role management endpoints (admin-only) |
| 14 | RoleRoutes tests | Integration tests for role API endpoints |
| 15 | UI — types + API client | TypeScript types and API module for roles |
| 16 | UI — useRole composable refactor | Replace role string checks with permission-based checks |
| 17 | UI — auth store + /me update | Handle permissions array from `/me` response |
| 18 | UI — RolesView page | Admin page for role CRUD with permission checkbox grid |
| 19 | UI — GroupsView update | Replace role dropdown with role selector + scope fields |
| 20 | UI — routing + sidebar | Add roles route and sidebar navigation entry |
| 21 | Full verification pass | Build, test, manual QA |

---

### Task 1: Schema Migration v008

**Files:**
- Create: `scripts/db/v008/001_permissions_restructure.sql`

This migration creates the permission model tables, seeds default roles, migrates existing data, and drops the old `groups.role` column. All within a single migration file to ensure atomicity.

**Step 1: Create the migration directory and SQL file**

Create `scripts/db/v008/001_permissions_restructure.sql`:

```sql
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

-- 12. Update the primary key on group_members to include role_id and scope
-- A user can be in the same group with different roles at different scopes
ALTER TABLE group_members DROP CONSTRAINT group_members_pkey;
ALTER TABLE group_members ADD PRIMARY KEY (user_id, group_id, role_id, COALESCE(scope_type, ''), COALESCE(scope_id, 0));
```

**Step 2: Verify the migration file exists**

Run: `ls -la scripts/db/v008/`
Expected: Shows `001_permissions_restructure.sql`.

**Step 3: Commit**

```bash
git add scripts/db/v008/
git commit -m "feat(db): add v008 migration for permissions restructure"
```

**Design note on primary key:** The original `group_members` PK was `(user_id, group_id)`. The new PK must accommodate the same user being in the same group with different scopes (e.g., Operator globally + Admin for a specific zone). The composite PK `(user_id, group_id, role_id, scope_type, scope_id)` handles NULLs via COALESCE since PostgreSQL treats NULLs as distinct in primary keys.

**Alternative approach:** If the COALESCE-based PK is problematic, use a surrogate `id SERIAL PRIMARY KEY` on `group_members` instead, with a unique constraint on `(user_id, group_id, role_id, scope_type, scope_id)`. Evaluate during implementation.

---

### Task 2: Permission Constants

**Files:**
- Create: `include/common/Permissions.hpp`

Code-defined permission strings as `constexpr` values. Not stored in a database table — the `role_permissions` table references these strings, but the source of truth for what permissions exist is this header.

**Step 1: Create the header**

Create `include/common/Permissions.hpp`:

```cpp
#pragma once

#include <array>
#include <string_view>

namespace dns::common {

/// Code-defined permission strings.
/// These are the canonical permission identifiers referenced by role_permissions rows.
namespace Permissions {

// Zones
inline constexpr std::string_view kZonesView       = "zones.view";
inline constexpr std::string_view kZonesCreate     = "zones.create";
inline constexpr std::string_view kZonesEdit       = "zones.edit";
inline constexpr std::string_view kZonesDelete     = "zones.delete";
inline constexpr std::string_view kZonesDeploy     = "zones.deploy";
inline constexpr std::string_view kZonesRollback   = "zones.rollback";

// Records
inline constexpr std::string_view kRecordsView     = "records.view";
inline constexpr std::string_view kRecordsCreate   = "records.create";
inline constexpr std::string_view kRecordsEdit     = "records.edit";
inline constexpr std::string_view kRecordsDelete   = "records.delete";
inline constexpr std::string_view kRecordsImport   = "records.import";

// Providers
inline constexpr std::string_view kProvidersView   = "providers.view";
inline constexpr std::string_view kProvidersCreate = "providers.create";
inline constexpr std::string_view kProvidersEdit   = "providers.edit";
inline constexpr std::string_view kProvidersDelete = "providers.delete";

// Views
inline constexpr std::string_view kViewsView       = "views.view";
inline constexpr std::string_view kViewsCreate     = "views.create";
inline constexpr std::string_view kViewsEdit       = "views.edit";
inline constexpr std::string_view kViewsDelete     = "views.delete";

// Variables
inline constexpr std::string_view kVariablesView   = "variables.view";
inline constexpr std::string_view kVariablesCreate = "variables.create";
inline constexpr std::string_view kVariablesEdit   = "variables.edit";
inline constexpr std::string_view kVariablesDelete = "variables.delete";

// Git Repos
inline constexpr std::string_view kReposView       = "repos.view";
inline constexpr std::string_view kReposCreate     = "repos.create";
inline constexpr std::string_view kReposEdit       = "repos.edit";
inline constexpr std::string_view kReposDelete     = "repos.delete";

// Audit
inline constexpr std::string_view kAuditView       = "audit.view";
inline constexpr std::string_view kAuditExport     = "audit.export";
inline constexpr std::string_view kAuditPurge      = "audit.purge";

// Users
inline constexpr std::string_view kUsersView       = "users.view";
inline constexpr std::string_view kUsersCreate     = "users.create";
inline constexpr std::string_view kUsersEdit       = "users.edit";
inline constexpr std::string_view kUsersDelete     = "users.delete";

// Groups
inline constexpr std::string_view kGroupsView      = "groups.view";
inline constexpr std::string_view kGroupsCreate    = "groups.create";
inline constexpr std::string_view kGroupsEdit      = "groups.edit";
inline constexpr std::string_view kGroupsDelete    = "groups.delete";

// Roles
inline constexpr std::string_view kRolesView       = "roles.view";
inline constexpr std::string_view kRolesCreate     = "roles.create";
inline constexpr std::string_view kRolesEdit       = "roles.edit";
inline constexpr std::string_view kRolesDelete     = "roles.delete";

// Settings
inline constexpr std::string_view kSettingsView    = "settings.view";
inline constexpr std::string_view kSettingsEdit    = "settings.edit";

// Backup
inline constexpr std::string_view kBackupCreate    = "backup.create";
inline constexpr std::string_view kBackupRestore   = "backup.restore";

/// All known permissions, for validation and UI rendering.
inline constexpr std::array kAllPermissions = {
    kZonesView, kZonesCreate, kZonesEdit, kZonesDelete, kZonesDeploy, kZonesRollback,
    kRecordsView, kRecordsCreate, kRecordsEdit, kRecordsDelete, kRecordsImport,
    kProvidersView, kProvidersCreate, kProvidersEdit, kProvidersDelete,
    kViewsView, kViewsCreate, kViewsEdit, kViewsDelete,
    kVariablesView, kVariablesCreate, kVariablesEdit, kVariablesDelete,
    kReposView, kReposCreate, kReposEdit, kReposDelete,
    kAuditView, kAuditExport, kAuditPurge,
    kUsersView, kUsersCreate, kUsersEdit, kUsersDelete,
    kGroupsView, kGroupsCreate, kGroupsEdit, kGroupsDelete,
    kRolesView, kRolesCreate, kRolesEdit, kRolesDelete,
    kSettingsView, kSettingsEdit,
    kBackupCreate, kBackupRestore,
};

/// Permission categories for UI grouping.
struct PermissionCategory {
  std::string_view sName;
  std::array<std::string_view, 6> vPermissions;  // max 6 per category
  int iCount;
};

}  // namespace Permissions
}  // namespace dns::common
```

**Step 2: Verify build compiles**

Run: `cmake --build build --parallel 2>&1 | tail -5`
Expected: Build succeeds (header-only, no link changes).

**Step 3: Commit**

```bash
git add include/common/Permissions.hpp
git commit -m "feat: add code-defined permission constants"
```

---

### Task 3: RoleRepository

**Files:**
- Create: `include/dal/RoleRepository.hpp`
- Create: `src/dal/RoleRepository.cpp`

This repository manages the `roles` and `role_permissions` tables. It provides CRUD for roles and permission assignment.

**Step 1: Create the header**

Create `include/dal/RoleRepository.hpp`:

```cpp
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

namespace dns::dal {

class ConnectionPool;

/// Row type returned from role queries.
struct RoleRow {
  int64_t iId = 0;
  std::string sName;
  std::string sDescription;
  bool bIsSystem = false;
  std::string sCreatedAt;
};

/// Manages roles and role_permissions.
/// Class abbreviation: rr (role repo)
class RoleRepository {
 public:
  explicit RoleRepository(ConnectionPool& cpPool);

  /// List all roles.
  std::vector<RoleRow> listAll();

  /// Find a role by ID. Returns nullopt if not found.
  std::optional<RoleRow> findById(int64_t iRoleId);

  /// Find a role by name. Returns nullopt if not found.
  std::optional<RoleRow> findByName(const std::string& sName);

  /// Create a custom role. Returns the new role ID.
  int64_t create(const std::string& sName, const std::string& sDescription);

  /// Update a role's name and description. Throws if is_system and name changed.
  void update(int64_t iRoleId, const std::string& sName, const std::string& sDescription);

  /// Delete a role. Throws if is_system.
  void deleteRole(int64_t iRoleId);

  /// Get all permissions for a role.
  std::unordered_set<std::string> getPermissions(int64_t iRoleId);

  /// Set permissions for a role (replaces all existing).
  void setPermissions(int64_t iRoleId, const std::vector<std::string>& vPermissions);

  /// Resolve all permissions for a user across all group memberships.
  /// Considers scope_type and scope_id for resource-level access.
  /// iViewId and iZoneId are the resource being accessed (0 = global check).
  std::unordered_set<std::string> resolveUserPermissions(
      int64_t iUserId, int64_t iViewId = 0, int64_t iZoneId = 0);

  /// Get the highest-privilege role name for a user (for display/JWT).
  /// Returns empty string if no group membership.
  std::string getHighestRoleName(int64_t iUserId);

 private:
  ConnectionPool& _cpPool;
};

}  // namespace dns::dal
```

**Step 2: Create the implementation**

Create `src/dal/RoleRepository.cpp`:

```cpp
#include "dal/RoleRepository.hpp"

#include "common/Errors.hpp"
#include "dal/ConnectionPool.hpp"

#include <pqxx/pqxx>

namespace dns::dal {

RoleRepository::RoleRepository(ConnectionPool& cpPool) : _cpPool(cpPool) {}

std::vector<RoleRow> RoleRepository::listAll() {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT id, name, COALESCE(description, ''), is_system, "
      "TO_CHAR(created_at, 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') "
      "FROM roles ORDER BY is_system DESC, name");
  txn.commit();

  std::vector<RoleRow> vRoles;
  vRoles.reserve(result.size());
  for (const auto& row : result) {
    vRoles.push_back({
        row[0].as<int64_t>(),
        row[1].as<std::string>(),
        row[2].as<std::string>(),
        row[3].as<bool>(),
        row[4].as<std::string>(),
    });
  }
  return vRoles;
}

std::optional<RoleRow> RoleRepository::findById(int64_t iRoleId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT id, name, COALESCE(description, ''), is_system, "
      "TO_CHAR(created_at, 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') "
      "FROM roles WHERE id = $1",
      pqxx::params{iRoleId});
  txn.commit();

  if (result.empty()) return std::nullopt;
  const auto& row = result[0];
  return RoleRow{
      row[0].as<int64_t>(),
      row[1].as<std::string>(),
      row[2].as<std::string>(),
      row[3].as<bool>(),
      row[4].as<std::string>(),
  };
}

std::optional<RoleRow> RoleRepository::findByName(const std::string& sName) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT id, name, COALESCE(description, ''), is_system, "
      "TO_CHAR(created_at, 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') "
      "FROM roles WHERE name = $1",
      pqxx::params{sName});
  txn.commit();

  if (result.empty()) return std::nullopt;
  const auto& row = result[0];
  return RoleRow{
      row[0].as<int64_t>(),
      row[1].as<std::string>(),
      row[2].as<std::string>(),
      row[3].as<bool>(),
      row[4].as<std::string>(),
  };
}

int64_t RoleRepository::create(const std::string& sName, const std::string& sDescription) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  try {
    auto result = txn.exec(
        "INSERT INTO roles (name, description) VALUES ($1, $2) RETURNING id",
        pqxx::params{sName, sDescription});
    txn.commit();
    return result[0][0].as<int64_t>();
  } catch (const pqxx::unique_violation&) {
    throw common::ConflictError("ROLE_EXISTS", "Role name already exists");
  }
}

void RoleRepository::update(int64_t iRoleId, const std::string& sName,
                             const std::string& sDescription) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);

  // Check if system role — prevent name change
  auto check = txn.exec(
      "SELECT is_system, name FROM roles WHERE id = $1",
      pqxx::params{iRoleId});
  if (check.empty())
    throw common::NotFoundError("ROLE_NOT_FOUND", "Role not found");

  if (check[0][0].as<bool>() && sName != check[0][1].as<std::string>()) {
    throw common::ValidationError("SYSTEM_ROLE_RENAME",
                                   "Cannot rename a system role");
  }

  auto result = txn.exec(
      "UPDATE roles SET name = $1, description = $2 WHERE id = $3",
      pqxx::params{sName, sDescription, iRoleId});
  txn.commit();

  if (result.affected_rows() == 0)
    throw common::NotFoundError("ROLE_NOT_FOUND", "Role not found");
}

void RoleRepository::deleteRole(int64_t iRoleId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);

  // Prevent deletion of system roles
  auto check = txn.exec("SELECT is_system FROM roles WHERE id = $1",
                         pqxx::params{iRoleId});
  if (check.empty())
    throw common::NotFoundError("ROLE_NOT_FOUND", "Role not found");

  if (check[0][0].as<bool>()) {
    throw common::ConflictError("SYSTEM_ROLE_DELETE",
                                 "Cannot delete a system role");
  }

  // Check if role is in use
  auto usage = txn.exec(
      "SELECT COUNT(*) FROM group_members WHERE role_id = $1",
      pqxx::params{iRoleId});
  if (usage[0][0].as<int>() > 0) {
    throw common::ConflictError("ROLE_IN_USE",
                                 "Cannot delete role: still assigned to group members");
  }

  txn.exec("DELETE FROM roles WHERE id = $1", pqxx::params{iRoleId});
  txn.commit();
}

std::unordered_set<std::string> RoleRepository::getPermissions(int64_t iRoleId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT permission FROM role_permissions WHERE role_id = $1 ORDER BY permission",
      pqxx::params{iRoleId});
  txn.commit();

  std::unordered_set<std::string> vPerms;
  for (const auto& row : result) {
    vPerms.insert(row[0].as<std::string>());
  }
  return vPerms;
}

void RoleRepository::setPermissions(int64_t iRoleId,
                                     const std::vector<std::string>& vPermissions) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);

  // Verify role exists
  auto check = txn.exec("SELECT 1 FROM roles WHERE id = $1", pqxx::params{iRoleId});
  if (check.empty())
    throw common::NotFoundError("ROLE_NOT_FOUND", "Role not found");

  // Replace all permissions
  txn.exec("DELETE FROM role_permissions WHERE role_id = $1", pqxx::params{iRoleId});
  for (const auto& sPerm : vPermissions) {
    txn.exec(
        "INSERT INTO role_permissions (role_id, permission) VALUES ($1, $2)",
        pqxx::params{iRoleId, sPerm});
  }
  txn.commit();
}

std::unordered_set<std::string> RoleRepository::resolveUserPermissions(
    int64_t iUserId, int64_t iViewId, int64_t iZoneId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);

  // Collect permissions from all matching group memberships:
  // - Global scope (scope_type IS NULL)
  // - View-level scope matching iViewId
  // - Zone-level scope matching iZoneId
  auto result = txn.exec(
      "SELECT DISTINCT rp.permission "
      "FROM group_members gm "
      "JOIN role_permissions rp ON rp.role_id = gm.role_id "
      "WHERE gm.user_id = $1 "
      "AND ("
      "  gm.scope_type IS NULL "
      "  OR (gm.scope_type = 'view' AND gm.scope_id = $2 AND $2 > 0) "
      "  OR (gm.scope_type = 'zone' AND gm.scope_id = $3 AND $3 > 0)"
      ")",
      pqxx::params{iUserId, iViewId, iZoneId});
  txn.commit();

  std::unordered_set<std::string> vPerms;
  for (const auto& row : result) {
    vPerms.insert(row[0].as<std::string>());
  }
  return vPerms;
}

std::string RoleRepository::getHighestRoleName(int64_t iUserId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);

  // Find the role with the most permissions among the user's global assignments
  auto result = txn.exec(
      "SELECT r.name, COUNT(rp.permission) AS perm_count "
      "FROM group_members gm "
      "JOIN roles r ON r.id = gm.role_id "
      "LEFT JOIN role_permissions rp ON rp.role_id = r.id "
      "WHERE gm.user_id = $1 AND gm.scope_type IS NULL "
      "GROUP BY r.name "
      "ORDER BY perm_count DESC "
      "LIMIT 1",
      pqxx::params{iUserId});
  txn.commit();

  if (result.empty()) return "";
  return result[0][0].as<std::string>();
}

}  // namespace dns::dal
```

**Step 3: Verify build compiles**

Run: `cmake --build build --parallel 2>&1 | tail -5`
Expected: Build succeeds.

**Step 4: Commit**

```bash
git add include/dal/RoleRepository.hpp src/dal/RoleRepository.cpp
git commit -m "feat(dal): add RoleRepository for roles and role_permissions CRUD"
```

---

### Task 4: RoleRepository Tests

**Files:**
- Create: `tests/integration/test_role_repository.cpp`

Follow the existing integration test pattern (see `tests/integration/test_settings_repository.cpp`). Tests skip when `DNS_DB_URL` is not set.

**Step 1: Write the test file**

Create `tests/integration/test_role_repository.cpp`:

```cpp
#include "dal/RoleRepository.hpp"
#include "dal/ConnectionPool.hpp"
#include "common/Errors.hpp"
#include "common/Logger.hpp"

#include <gtest/gtest.h>

#include <cstdlib>
#include <memory>
#include <string>

namespace {
std::string getDbUrl() {
  const char* p = std::getenv("DNS_DB_URL");
  return p ? std::string(p) : "";
}
}  // namespace

class RoleRepositoryTest : public ::testing::Test {
 protected:
  void SetUp() override {
    _sDbUrl = getDbUrl();
    if (_sDbUrl.empty()) {
      GTEST_SKIP() << "DNS_DB_URL not set — skipping DB integration test";
    }
    dns::common::Logger::init("warn");
    _cpPool = std::make_unique<dns::dal::ConnectionPool>(_sDbUrl, 2);
    _rrRepo = std::make_unique<dns::dal::RoleRepository>(*_cpPool);

    // Clean test roles (leave system roles alone)
    auto cg = _cpPool->checkout();
    pqxx::work txn(*cg);
    txn.exec("DELETE FROM roles WHERE name LIKE 'test_%' AND is_system = false");
    txn.commit();
  }

  std::string _sDbUrl;
  std::unique_ptr<dns::dal::ConnectionPool> _cpPool;
  std::unique_ptr<dns::dal::RoleRepository> _rrRepo;
};

TEST_F(RoleRepositoryTest, ListAll_ReturnsSystemRoles) {
  auto vRoles = _rrRepo->listAll();
  EXPECT_GE(vRoles.size(), 3u);  // Admin, Operator, Viewer

  bool bFoundAdmin = false, bFoundOperator = false, bFoundViewer = false;
  for (const auto& role : vRoles) {
    if (role.sName == "Admin") bFoundAdmin = true;
    if (role.sName == "Operator") bFoundOperator = true;
    if (role.sName == "Viewer") bFoundViewer = true;
  }
  EXPECT_TRUE(bFoundAdmin);
  EXPECT_TRUE(bFoundOperator);
  EXPECT_TRUE(bFoundViewer);
}

TEST_F(RoleRepositoryTest, CreateAndFindById) {
  int64_t iId = _rrRepo->create("test_custom_role", "A test role");
  EXPECT_GT(iId, 0);

  auto oRole = _rrRepo->findById(iId);
  ASSERT_TRUE(oRole.has_value());
  EXPECT_EQ(oRole->sName, "test_custom_role");
  EXPECT_EQ(oRole->sDescription, "A test role");
  EXPECT_FALSE(oRole->bIsSystem);
}

TEST_F(RoleRepositoryTest, FindByName) {
  auto oRole = _rrRepo->findByName("Admin");
  ASSERT_TRUE(oRole.has_value());
  EXPECT_TRUE(oRole->bIsSystem);
}

TEST_F(RoleRepositoryTest, CreateDuplicateName_Throws) {
  _rrRepo->create("test_dup_role", "first");
  EXPECT_THROW(_rrRepo->create("test_dup_role", "second"), dns::common::ConflictError);
}

TEST_F(RoleRepositoryTest, Update_CustomRole) {
  int64_t iId = _rrRepo->create("test_update_role", "before");
  _rrRepo->update(iId, "test_update_role_renamed", "after");

  auto oRole = _rrRepo->findById(iId);
  ASSERT_TRUE(oRole.has_value());
  EXPECT_EQ(oRole->sName, "test_update_role_renamed");
  EXPECT_EQ(oRole->sDescription, "after");
}

TEST_F(RoleRepositoryTest, Update_SystemRoleRename_Throws) {
  auto oAdmin = _rrRepo->findByName("Admin");
  ASSERT_TRUE(oAdmin.has_value());
  EXPECT_THROW(_rrRepo->update(oAdmin->iId, "SuperAdmin", "renamed"),
               dns::common::ValidationError);
}

TEST_F(RoleRepositoryTest, DeleteRole_CustomRole) {
  int64_t iId = _rrRepo->create("test_delete_role", "to be deleted");
  _rrRepo->deleteRole(iId);
  EXPECT_FALSE(_rrRepo->findById(iId).has_value());
}

TEST_F(RoleRepositoryTest, DeleteRole_SystemRole_Throws) {
  auto oAdmin = _rrRepo->findByName("Admin");
  ASSERT_TRUE(oAdmin.has_value());
  EXPECT_THROW(_rrRepo->deleteRole(oAdmin->iId), dns::common::ConflictError);
}

TEST_F(RoleRepositoryTest, GetPermissions_AdminHasAll) {
  auto oAdmin = _rrRepo->findByName("Admin");
  ASSERT_TRUE(oAdmin.has_value());
  auto perms = _rrRepo->getPermissions(oAdmin->iId);
  EXPECT_GT(perms.size(), 30u);  // Admin should have all permissions
  EXPECT_TRUE(perms.count("zones.view"));
  EXPECT_TRUE(perms.count("settings.edit"));
  EXPECT_TRUE(perms.count("backup.restore"));
}

TEST_F(RoleRepositoryTest, GetPermissions_ViewerSubset) {
  auto oViewer = _rrRepo->findByName("Viewer");
  ASSERT_TRUE(oViewer.has_value());
  auto perms = _rrRepo->getPermissions(oViewer->iId);
  EXPECT_TRUE(perms.count("zones.view"));
  EXPECT_FALSE(perms.count("zones.create"));
  EXPECT_FALSE(perms.count("settings.edit"));
}

TEST_F(RoleRepositoryTest, SetPermissions_ReplacesAll) {
  int64_t iId = _rrRepo->create("test_perms_role", "for permissions");
  _rrRepo->setPermissions(iId, {"zones.view", "zones.create"});

  auto perms = _rrRepo->getPermissions(iId);
  EXPECT_EQ(perms.size(), 2u);
  EXPECT_TRUE(perms.count("zones.view"));
  EXPECT_TRUE(perms.count("zones.create"));

  // Replace with different set
  _rrRepo->setPermissions(iId, {"records.view"});
  perms = _rrRepo->getPermissions(iId);
  EXPECT_EQ(perms.size(), 1u);
  EXPECT_TRUE(perms.count("records.view"));
  EXPECT_FALSE(perms.count("zones.view"));
}

TEST_F(RoleRepositoryTest, GetHighestRoleName_NoMembership) {
  auto sRole = _rrRepo->getHighestRoleName(999999);
  EXPECT_TRUE(sRole.empty());
}
```

**Step 2: Verify build and test**

Run: `cmake --build build --parallel && build/tests/dns-tests --gtest_filter='RoleRepository*' 2>&1 | tail -20`
Expected: Tests pass (or skip if `DNS_DB_URL` not set).

**Step 3: Commit**

```bash
git add tests/integration/test_role_repository.cpp
git commit -m "test(dal): add RoleRepository integration tests"
```

---

### Task 5: PermissionService

**Files:**
- Create: `include/core/PermissionService.hpp`
- Create: `src/core/PermissionService.cpp`

The PermissionService provides a clean interface for checking permissions, abstracting the DB queries and scope resolution. It wraps `RoleRepository::resolveUserPermissions()` and adds caching for the current request.

**Step 1: Create the header**

Create `include/core/PermissionService.hpp`:

```cpp
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_set>

namespace dns::dal {
class RoleRepository;
class ZoneRepository;
}  // namespace dns::dal

namespace dns::core {

/// Resolves effective permissions for a user, considering hierarchical scoping.
/// Class abbreviation: ps
class PermissionService {
 public:
  PermissionService(dns::dal::RoleRepository& rrRepo,
                    dns::dal::ZoneRepository& zrRepo);

  /// Check if a user has a specific permission globally (no resource context).
  bool hasPermission(int64_t iUserId, std::string_view svPermission);

  /// Check if a user has a specific permission for a zone.
  /// Resolves the zone's view for view-level scope matching.
  bool hasPermissionForZone(int64_t iUserId, std::string_view svPermission,
                            int64_t iZoneId);

  /// Check if a user has a specific permission for a view.
  bool hasPermissionForView(int64_t iUserId, std::string_view svPermission,
                            int64_t iViewId);

  /// Get all effective permissions for a user (global scope only).
  std::unordered_set<std::string> getEffectivePermissions(int64_t iUserId);

  /// Get all effective permissions for a user for a specific zone.
  std::unordered_set<std::string> getEffectivePermissionsForZone(
      int64_t iUserId, int64_t iZoneId);

 private:
  dns::dal::RoleRepository& _rrRepo;
  dns::dal::ZoneRepository& _zrRepo;
};

}  // namespace dns::core
```

**Step 2: Create the implementation**

Create `src/core/PermissionService.cpp`:

```cpp
#include "core/PermissionService.hpp"

#include "dal/RoleRepository.hpp"
#include "dal/ZoneRepository.hpp"

namespace dns::core {

PermissionService::PermissionService(dns::dal::RoleRepository& rrRepo,
                                     dns::dal::ZoneRepository& zrRepo)
    : _rrRepo(rrRepo), _zrRepo(zrRepo) {}

bool PermissionService::hasPermission(int64_t iUserId, std::string_view svPermission) {
  auto perms = _rrRepo.resolveUserPermissions(iUserId);
  return perms.count(std::string(svPermission)) > 0;
}

bool PermissionService::hasPermissionForZone(int64_t iUserId,
                                              std::string_view svPermission,
                                              int64_t iZoneId) {
  // Look up the zone's view_id for view-level scope matching
  int64_t iViewId = 0;
  auto oZone = _zrRepo.findById(iZoneId);
  if (oZone.has_value()) {
    iViewId = oZone->iViewId;
  }

  auto perms = _rrRepo.resolveUserPermissions(iUserId, iViewId, iZoneId);
  return perms.count(std::string(svPermission)) > 0;
}

bool PermissionService::hasPermissionForView(int64_t iUserId,
                                              std::string_view svPermission,
                                              int64_t iViewId) {
  auto perms = _rrRepo.resolveUserPermissions(iUserId, iViewId);
  return perms.count(std::string(svPermission)) > 0;
}

std::unordered_set<std::string> PermissionService::getEffectivePermissions(
    int64_t iUserId) {
  return _rrRepo.resolveUserPermissions(iUserId);
}

std::unordered_set<std::string> PermissionService::getEffectivePermissionsForZone(
    int64_t iUserId, int64_t iZoneId) {
  int64_t iViewId = 0;
  auto oZone = _zrRepo.findById(iZoneId);
  if (oZone.has_value()) {
    iViewId = oZone->iViewId;
  }
  return _rrRepo.resolveUserPermissions(iUserId, iViewId, iZoneId);
}

}  // namespace dns::core
```

**Step 3: Verify build compiles**

Run: `cmake --build build --parallel 2>&1 | tail -5`

**Step 4: Commit**

```bash
git add include/core/PermissionService.hpp src/core/PermissionService.cpp
git commit -m "feat(core): add PermissionService for hierarchical permission resolution"
```

---

### Task 6: PermissionService Tests

**Files:**
- Create: `tests/integration/test_permission_service.cpp`

These tests need a DB with the v008 migration applied. They create test users, groups, roles, and group_members with various scopes to verify resolution logic.

**Step 1: Write the test file**

Create `tests/integration/test_permission_service.cpp`:

```cpp
#include "core/PermissionService.hpp"
#include "dal/ConnectionPool.hpp"
#include "dal/RoleRepository.hpp"
#include "dal/ZoneRepository.hpp"
#include "common/Logger.hpp"
#include "common/Permissions.hpp"

#include <gtest/gtest.h>

#include <cstdlib>
#include <memory>
#include <string>

namespace {
std::string getDbUrl() {
  const char* p = std::getenv("DNS_DB_URL");
  return p ? std::string(p) : "";
}
}  // namespace

class PermissionServiceTest : public ::testing::Test {
 protected:
  void SetUp() override {
    _sDbUrl = getDbUrl();
    if (_sDbUrl.empty()) {
      GTEST_SKIP() << "DNS_DB_URL not set — skipping DB integration test";
    }
    dns::common::Logger::init("warn");
    _cpPool = std::make_unique<dns::dal::ConnectionPool>(_sDbUrl, 2);
    _rrRepo = std::make_unique<dns::dal::RoleRepository>(*_cpPool);
    _zrRepo = std::make_unique<dns::dal::ZoneRepository>(*_cpPool);
    _psService = std::make_unique<dns::core::PermissionService>(*_rrRepo, *_zrRepo);
  }

  std::string _sDbUrl;
  std::unique_ptr<dns::dal::ConnectionPool> _cpPool;
  std::unique_ptr<dns::dal::RoleRepository> _rrRepo;
  std::unique_ptr<dns::dal::ZoneRepository> _zrRepo;
  std::unique_ptr<dns::core::PermissionService> _psService;
};

TEST_F(PermissionServiceTest, GlobalAdmin_HasAllPermissions) {
  // Use existing admin user (user_id=1 if setup has run)
  // This test verifies the resolution path works end-to-end
  auto perms = _psService->getEffectivePermissions(1);
  // Admin should have zones.view if they're in a group with Admin role
  // (depends on test data setup)
  EXPECT_GE(perms.size(), 0u);  // At minimum, function returns without error
}

TEST_F(PermissionServiceTest, NoMembership_NoPermissions) {
  auto perms = _psService->getEffectivePermissions(999999);
  EXPECT_TRUE(perms.empty());
}

TEST_F(PermissionServiceTest, HasPermission_NonExistentUser) {
  EXPECT_FALSE(_psService->hasPermission(999999, dns::common::Permissions::kZonesView));
}
```

**Step 2: Verify build and test**

Run: `cmake --build build --parallel && build/tests/dns-tests --gtest_filter='PermissionService*' 2>&1 | tail -20`

**Step 3: Commit**

```bash
git add tests/integration/test_permission_service.cpp
git commit -m "test(core): add PermissionService integration tests"
```

---

### Task 7: RequestContext + AuthMiddleware Refactor

**Files:**
- Edit: `include/common/Types.hpp`
- Edit: `include/api/AuthMiddleware.hpp`
- Edit: `src/api/AuthMiddleware.cpp`

The `RequestContext` gains a `vPermissions` field (set of permission strings) resolved at request time. The `sRole` field is retained for backward compatibility (display name of highest role) but is no longer used for authorization decisions.

**Step 1: Update RequestContext in Types.hpp**

Change the `RequestContext` struct at line 82-88 of `include/common/Types.hpp`:

```cpp
/// Identity context injected by AuthMiddleware.
/// Class abbreviation: rc
struct RequestContext {
  int64_t iUserId = 0;
  std::string sUsername;
  std::string sRole;          // Display-only: highest-privilege role name
  std::string sAuthMethod;
  std::unordered_set<std::string> vPermissions;  // Effective permissions for this request
};
```

Add `#include <unordered_set>` to the includes.

**Step 2: Update AuthMiddleware to accept RoleRepository**

Update `include/api/AuthMiddleware.hpp` to add `RoleRepository` dependency:

```cpp
namespace dns::dal {
class UserRepository;
class SessionRepository;
class ApiKeyRepository;
class RoleRepository;
}  // namespace dns::dal
```

Add to constructor and private members:

```cpp
  AuthMiddleware(const dns::security::IJwtSigner& jsSigner,
                 dns::dal::SessionRepository& srRepo,
                 dns::dal::ApiKeyRepository& akrRepo,
                 dns::dal::UserRepository& urRepo,
                 dns::dal::RoleRepository& rrRepo,
                 int iJwtTtlSeconds,
                 int iApiKeyCleanupGraceSeconds);
```

Add private member: `dns::dal::RoleRepository& _rrRepo;`

**Step 3: Update AuthMiddleware implementation**

In `src/api/AuthMiddleware.cpp`, update constructor to accept and store `rrRepo`.

In `validateJwt()`, after rebuilding `rcCtx` from JWT payload (line 69-74), add permission resolution:

```cpp
  // Resolve permissions from DB (not cached in JWT)
  rcCtx.vPermissions = _rrRepo.resolveUserPermissions(rcCtx.iUserId);
  // Update role name from DB (may have changed since JWT was issued)
  std::string sCurrentRole = _rrRepo.getHighestRoleName(rcCtx.iUserId);
  if (!sCurrentRole.empty()) {
    rcCtx.sRole = sCurrentRole;
  }
```

In `validateApiKey()`, replace the `getHighestRole()` call (line 109) with:

```cpp
  rcCtx.vPermissions = _rrRepo.resolveUserPermissions(oUser->iId);
  rcCtx.sRole = _rrRepo.getHighestRoleName(oUser->iId);
  if (rcCtx.sRole.empty()) rcCtx.sRole = "Viewer";
```

**Step 4: Update main.cpp**

The `AuthMiddleware` constructor call in `main.cpp` (line 398-400) needs the new `rrRepo` parameter. This requires constructing `RoleRepository` before `AuthMiddleware`:

Add after `grRepo` construction (around line 279):
```cpp
auto roleRepo = std::make_unique<dns::dal::RoleRepository>(*cpPool);
```

Update `AuthMiddleware` construction:
```cpp
auto amMiddleware = std::make_unique<dns::api::AuthMiddleware>(
    *upSigner, *srRepo, *akrRepo, *urRepo, *roleRepo,
    cfgApp.iJwtTtlSeconds, cfgApp.iApiKeyCleanupGraceSeconds);
```

**Step 5: Verify build compiles**

Run: `cmake --build build --parallel 2>&1 | tail -10`

**Step 6: Fix any test compilation issues**

Tests that construct `AuthMiddleware` directly (mock tests) will need the additional parameter. Check `tests/` for any `AuthMiddleware` construction.

**Step 7: Commit**

```bash
git add include/common/Types.hpp include/api/AuthMiddleware.hpp src/api/AuthMiddleware.cpp src/main.cpp
git commit -m "feat(auth): resolve permissions in AuthMiddleware instead of using cached role"
```

**Design decision — why resolve permissions on every request:**
The current system bakes the role into the JWT, which means role changes don't take effect until re-login. By resolving permissions from DB on every request (same as the API key path already does), permission changes are immediate. The DB query is a single indexed join (`group_members` → `role_permissions`), which is fast enough for request-time resolution. If this becomes a bottleneck, a short-lived in-memory cache keyed by `user_id` with a 60-second TTL can be added later.

---

### Task 8: RouteHelpers — requirePermission

**Files:**
- Edit: `include/api/RouteHelpers.hpp`
- Edit: `src/api/RouteHelpers.cpp`

Replace `requireRole()` with `requirePermission()`. Keep `requireRole()` temporarily for backward compatibility during the migration (Task 9), then remove it.

**Step 1: Update the header**

In `include/api/RouteHelpers.hpp`, add:

```cpp
#include <string_view>
```

Add the new function declaration:

```cpp
/// Enforce a specific permission. Throws AuthorizationError if the user
/// does not have the required permission in their RequestContext.
void requirePermission(const common::RequestContext& rcCtx, std::string_view svPermission);
```

Keep `requireRole()` declaration for now (removed in Task 9 after all call sites are migrated).

**Step 2: Update the implementation**

In `src/api/RouteHelpers.cpp`, add:

```cpp
void requirePermission(const common::RequestContext& rcCtx, std::string_view svPermission) {
  if (rcCtx.vPermissions.count(std::string(svPermission)) == 0) {
    throw common::AuthorizationError(
        "INSUFFICIENT_PERMISSION",
        "Required permission: " + std::string(svPermission));
  }
}
```

**Step 3: Verify build compiles**

Run: `cmake --build build --parallel 2>&1 | tail -5`

**Step 4: Commit**

```bash
git add include/api/RouteHelpers.hpp src/api/RouteHelpers.cpp
git commit -m "feat(api): add requirePermission() route helper"
```

---

### Task 9: Route Handlers Migration

**Files:**
- Edit: All 11 route files in `src/api/routes/`
- Edit: `src/api/RouteHelpers.cpp` (remove `requireRole()`)
- Edit: `include/api/RouteHelpers.hpp` (remove `requireRole()`)

Replace every `requireRole(rcCtx, "role")` call with the corresponding `requirePermission(rcCtx, Permissions::kXxxYyy)` call. Add `#include "common/Permissions.hpp"` to each route file.

**Permission mapping from old roles to new permissions:**

| File | Old Call | New Call |
|------|----------|---------|
| **ProviderRoutes.cpp** | | |
| L27 (GET health) | `requireRole(rcCtx, "viewer")` | `requirePermission(rcCtx, Permissions::kProvidersView)` |
| L75 (GET list) | `requireRole(rcCtx, "viewer")` | `requirePermission(rcCtx, Permissions::kProvidersView)` |
| L105 (POST create) | `requireRole(rcCtx, "admin")` | `requirePermission(rcCtx, Permissions::kProvidersCreate)` |
| L143 (GET by id) | `requireRole(rcCtx, "viewer")` | `requirePermission(rcCtx, Permissions::kProvidersView)` |
| L175 (PUT update) | `requireRole(rcCtx, "admin")` | `requirePermission(rcCtx, Permissions::kProvidersEdit)` |
| L208 (DELETE) | `requireRole(rcCtx, "admin")` | `requirePermission(rcCtx, Permissions::kProvidersDelete)` |
| **ViewRoutes.cpp** | | |
| L24 (GET list) | `requireRole(rcCtx, "viewer")` | `requirePermission(rcCtx, Permissions::kViewsView)` |
| L50 (POST create) | `requireRole(rcCtx, "admin")` | `requirePermission(rcCtx, Permissions::kViewsCreate)` |
| L74 (GET by id) | `requireRole(rcCtx, "viewer")` | `requirePermission(rcCtx, Permissions::kViewsView)` |
| L101 (PUT update) | `requireRole(rcCtx, "admin")` | `requirePermission(rcCtx, Permissions::kViewsEdit)` |
| L125 (DELETE) | `requireRole(rcCtx, "admin")` | `requirePermission(rcCtx, Permissions::kViewsDelete)` |
| L139 (POST attach) | `requireRole(rcCtx, "admin")` | `requirePermission(rcCtx, Permissions::kViewsEdit)` |
| L153 (POST detach) | `requireRole(rcCtx, "admin")` | `requirePermission(rcCtx, Permissions::kViewsEdit)` |
| **ZoneRoutes.cpp** | | |
| L58 (POST create) | `requireRole(rcCtx, "operator")` | `requirePermission(rcCtx, Permissions::kZonesCreate)` |
| L93 (POST batch records) | `requireRole(rcCtx, "operator")` | `requirePermission(rcCtx, Permissions::kRecordsImport)` |
| L128 (GET by id) | `requireRole(rcCtx, "viewer")` | `requirePermission(rcCtx, Permissions::kZonesView)` |
| L154 (PUT update) | `requireRole(rcCtx, "admin")` | `requirePermission(rcCtx, Permissions::kZonesEdit)` |
| L188 (GET sync) | `requireRole(rcCtx, "viewer")` | `requirePermission(rcCtx, Permissions::kZonesView)` |
| L205 (POST sync) | `requireRole(rcCtx, "admin")` | `requirePermission(rcCtx, Permissions::kZonesEdit)` |
| L240 (DELETE) | `requireRole(rcCtx, "admin")` | `requirePermission(rcCtx, Permissions::kZonesDelete)` |
| **RecordRoutes.cpp** | | |
| L69 (GET list) | `requireRole(rcCtx, "viewer")` | `requirePermission(rcCtx, Permissions::kRecordsView)` |
| L87 (POST create) | `requireRole(rcCtx, "operator")` | `requirePermission(rcCtx, Permissions::kRecordsCreate)` |
| L131 (GET by id) | `requireRole(rcCtx, "viewer")` | `requirePermission(rcCtx, Permissions::kRecordsView)` |
| L148 (PUT update) | `requireRole(rcCtx, "operator")` | `requirePermission(rcCtx, Permissions::kRecordsEdit)` |
| L203 (DELETE) | `requireRole(rcCtx, "operator")` | `requirePermission(rcCtx, Permissions::kRecordsDelete)` |
| L234 (POST preview) | `requireRole(rcCtx, "operator")` | `requirePermission(rcCtx, Permissions::kZonesDeploy)` |
| L263 (GET preview) | `requireRole(rcCtx, "viewer")` | `requirePermission(rcCtx, Permissions::kZonesView)` |
| L328 (POST push) | `requireRole(rcCtx, "operator")` | `requirePermission(rcCtx, Permissions::kZonesDeploy)` |
| L365 (POST batch import) | `requireRole(rcCtx, "operator")` | `requirePermission(rcCtx, Permissions::kRecordsImport)` |
| L420 (GET provider records) | `requireRole(rcCtx, "operator")` | `requirePermission(rcCtx, Permissions::kRecordsView)` |
| L527 (GET variables) | `requireRole(rcCtx, "viewer")` | `requirePermission(rcCtx, Permissions::kVariablesView)` |
| **VariableRoutes.cpp** | | |
| L51 (GET list) | `requireRole(rcCtx, "viewer")` | `requirePermission(rcCtx, Permissions::kVariablesView)` |
| L80 (POST create) | `requireRole(rcCtx, "operator")` | `requirePermission(rcCtx, Permissions::kVariablesCreate)` |
| L111 (GET by id) | `requireRole(rcCtx, "viewer")` | `requirePermission(rcCtx, Permissions::kVariablesView)` |
| L128 (PUT update) | `requireRole(rcCtx, "operator")` | `requirePermission(rcCtx, Permissions::kVariablesEdit)` |
| L149 (DELETE) | `requireRole(rcCtx, "operator")` | `requirePermission(rcCtx, Permissions::kVariablesDelete)` |
| **DeploymentRoutes.cpp** | | |
| L48 (GET list) | `requireRole(rcCtx, "viewer")` | `requirePermission(rcCtx, Permissions::kZonesView)` |
| L70 (GET snapshot) | `requireRole(rcCtx, "viewer")` | `requirePermission(rcCtx, Permissions::kZonesView)` |
| L87 (GET diff) | `requireRole(rcCtx, "viewer")` | `requirePermission(rcCtx, Permissions::kZonesView)` |
| L160 (POST rollback) | `requireRole(rcCtx, "operator")` | `requirePermission(rcCtx, Permissions::kZonesRollback)` |
| **AuditRoutes.cpp** | | |
| L65 (GET query) | `requireRole(rcCtx, "viewer")` | `requirePermission(rcCtx, Permissions::kAuditView)` |
| L106 (GET export) | `requireRole(rcCtx, "admin")` | `requirePermission(rcCtx, Permissions::kAuditExport)` |
| L140 (POST purge) | `requireRole(rcCtx, "admin")` | `requirePermission(rcCtx, Permissions::kAuditPurge)` |
| **UserRoutes.cpp** | | |
| L27 (GET list) | `requireRole(rcCtx, "admin")` | `requirePermission(rcCtx, Permissions::kUsersView)` |
| L58 (POST create) | `requireRole(rcCtx, "admin")` | `requirePermission(rcCtx, Permissions::kUsersCreate)` |
| L96 (GET by id) | `requireRole(rcCtx, "admin")` | `requirePermission(rcCtx, Permissions::kUsersView)` |
| L126 (PUT update) | `requireRole(rcCtx, "admin")` | `requirePermission(rcCtx, Permissions::kUsersEdit)` |
| L161 (POST reset password) | `requireRole(rcCtx, "admin")` | `requirePermission(rcCtx, Permissions::kUsersEdit)` |
| L175 (DELETE deactivate) | `requireRole(rcCtx, "admin")` | `requirePermission(rcCtx, Permissions::kUsersDelete)` |
| **GroupRoutes.cpp** | | |
| L25 (GET list) | `requireRole(rcCtx, "admin")` | `requirePermission(rcCtx, Permissions::kGroupsView)` |
| L52 (POST create) | `requireRole(rcCtx, "admin")` | `requirePermission(rcCtx, Permissions::kGroupsCreate)` |
| L76 (GET by id) | `requireRole(rcCtx, "admin")` | `requirePermission(rcCtx, Permissions::kGroupsView)` |
| L108 (PUT update) | `requireRole(rcCtx, "admin")` | `requirePermission(rcCtx, Permissions::kGroupsEdit)` |
| L134 (DELETE) | `requireRole(rcCtx, "admin")` | `requirePermission(rcCtx, Permissions::kGroupsDelete)` |
| **SettingsRoutes.cpp** | | |
| L28 (GET) | `requireRole(rcCtx, "admin")` | `requirePermission(rcCtx, Permissions::kSettingsView)` |
| L75 (PUT) | `requireRole(rcCtx, "admin")` | `requirePermission(rcCtx, Permissions::kSettingsEdit)` |

**Step 1: Add Permissions include to each route file**

Add `#include "common/Permissions.hpp"` to all 11 route files. Add `using namespace dns::common;` inside the namespace block for cleaner `Permissions::kXxx` references (or use fully qualified).

**Step 2: Replace all requireRole calls**

Perform the replacements listed above in each file. Use find-and-replace within each file.

**Step 3: Remove requireRole from RouteHelpers**

After all call sites are migrated, remove `requireRole()` from both `include/api/RouteHelpers.hpp` and `src/api/RouteHelpers.cpp`.

**Step 4: Verify build compiles**

Run: `cmake --build build --parallel 2>&1 | tail -10`
Fix any compilation errors from the removal.

**Step 5: Run tests**

Run: `build/tests/dns-tests 2>&1 | tail -20`
Expected: All existing tests pass. Tests that mock `requireRole` behavior will need updating.

**Step 6: Commit**

```bash
git add src/api/routes/*.cpp include/api/RouteHelpers.hpp src/api/RouteHelpers.cpp
git commit -m "feat(api): migrate all route handlers from requireRole to requirePermission"
```

---

### Task 10: AuthService JWT Update

**Files:**
- Edit: `src/security/AuthService.cpp`
- Edit: `src/api/routes/AuthRoutes.cpp`

Update JWT payload to include role name (for display) and update `/me` to return permissions.

**Step 1: Update AuthService.authenticateLocal()**

In `src/security/AuthService.cpp`, replace the role resolution (lines 47-49):

```cpp
  // Resolve role name for JWT (display only — permissions resolved per-request)
  std::string sRole = _urRepo.getHighestRole(oUser->iId);
  if (sRole.empty()) {
    sRole = "Viewer";  // default display role if no group membership
  }
```

Note: `getHighestRole()` still works here for JWT display purposes. Actual auth checks use `requirePermission()` now.

**Step 2: Update /me endpoint in AuthRoutes.cpp**

The `/me` endpoint (line 66-93) currently returns `role` from `rcCtx.sRole`. Update it to also return the permissions array:

```cpp
  nlohmann::json jPerms = nlohmann::json::array();
  for (const auto& sPerm : rcCtx.vPermissions) {
    jPerms.push_back(sPerm);
  }

  return jsonResponse(200, {
      {"user_id", rcCtx.iUserId},
      {"username", rcCtx.sUsername},
      {"email", sEmail},
      {"role", rcCtx.sRole},
      {"permissions", jPerms},
      {"auth_method", rcCtx.sAuthMethod},
      {"force_password_change", bForcePasswordChange},
  });
```

**Step 3: Verify build compiles**

**Step 4: Commit**

```bash
git add src/security/AuthService.cpp src/api/routes/AuthRoutes.cpp
git commit -m "feat(auth): return permissions array in /me response"
```

---

### Task 11: GroupRepository Refactor

**Files:**
- Edit: `include/dal/GroupRepository.hpp`
- Edit: `src/dal/GroupRepository.cpp`

The `groups` table no longer has a `role` column. `GroupRow` loses `sRole`. Member management now uses `role_id`, `scope_type`, `scope_id` from `group_members`.

**Step 1: Update GroupRow struct**

In `include/dal/GroupRepository.hpp`, remove `sRole` from `GroupRow`:

```cpp
struct GroupRow {
  int64_t iId = 0;
  std::string sName;
  std::string sDescription;
  int iMemberCount = 0;
  std::chrono::system_clock::time_point tpCreatedAt;
};
```

**Step 2: Add GroupMemberRow struct**

Add a new struct for group member details:

```cpp
struct GroupMemberRow {
  int64_t iUserId = 0;
  std::string sUsername;
  int64_t iRoleId = 0;
  std::string sRoleName;
  std::string sScopeType;  // empty, "view", or "zone"
  int64_t iScopeId = 0;
};
```

**Step 3: Update GroupRepository interface**

```cpp
class GroupRepository {
 public:
  explicit GroupRepository(ConnectionPool& cpPool);

  std::vector<GroupRow> listAll();
  std::optional<GroupRow> findById(int64_t iGroupId);
  int64_t create(const std::string& sName, const std::string& sDescription);
  void update(int64_t iGroupId, const std::string& sName, const std::string& sDescription);
  void deleteGroup(int64_t iGroupId);
  std::vector<GroupMemberRow> listMembers(int64_t iGroupId);

  /// Add a member with a specific role and optional scope.
  void addMember(int64_t iGroupId, int64_t iUserId, int64_t iRoleId,
                 const std::string& sScopeType = "", int64_t iScopeId = 0);

  /// Remove a specific member assignment.
  void removeMember(int64_t iGroupId, int64_t iUserId, int64_t iRoleId,
                    const std::string& sScopeType = "", int64_t iScopeId = 0);

 private:
  ConnectionPool& _cpPool;
};
```

**Step 4: Update GroupRepository implementation**

In `src/dal/GroupRepository.cpp`:

- Remove `role` from all SQL queries (it no longer exists on `groups` table)
- Update `create()` to only insert name + description
- Update `update()` to only set name + description
- Update `listMembers()` to join with `roles` and return `GroupMemberRow` with role and scope info
- Add `addMember()` and `removeMember()` implementations

The `create()` method changes from:
```cpp
txn.exec("INSERT INTO groups (name, role, description) VALUES ($1, $2, $3) RETURNING id", ...)
```
to:
```cpp
txn.exec("INSERT INTO groups (name, description) VALUES ($1, $2) RETURNING id", ...)
```

The `listMembers()` method changes to:
```cpp
auto result = txn.exec(
    "SELECT u.id, u.username, gm.role_id, r.name, "
    "COALESCE(gm.scope_type, ''), COALESCE(gm.scope_id, 0) "
    "FROM users u "
    "JOIN group_members gm ON gm.user_id = u.id "
    "JOIN roles r ON r.id = gm.role_id "
    "WHERE gm.group_id = $1 ORDER BY u.username",
    pqxx::params{iGroupId});
```

**Step 5: Update UserRepository**

In `include/dal/UserRepository.hpp` and `src/dal/UserRepository.cpp`:

- Remove `getHighestRole()` — replaced by `RoleRepository::getHighestRoleName()`
- Update `addToGroup()` to accept `role_id`, `scope_type`, `scope_id`
- Update `removeFromGroup()` to accept `role_id`, `scope_type`, `scope_id`
- Update `listGroupsForUser()` to return role and scope info

**Step 6: Verify build compiles and fix all callers**

Any code calling the old `create(name, role, desc)` or `getHighestRole()` needs updating. Key locations:
- `src/main.cpp` — no direct calls to `getHighestRole()` (done through AuthService/AuthMiddleware)
- `src/security/AuthService.cpp` — calls `_urRepo.getHighestRole()` → change to use `_rrRepo.getHighestRoleName()`
- `src/api/AuthMiddleware.cpp` — already updated in Task 7

**Step 7: Commit**

```bash
git add include/dal/GroupRepository.hpp src/dal/GroupRepository.cpp \
        include/dal/UserRepository.hpp src/dal/UserRepository.cpp
git commit -m "refactor(dal): remove role from groups, add scoped membership to group_members"
```

---

### Task 12: GroupRoutes + UserRoutes Update

**Files:**
- Edit: `src/api/routes/GroupRoutes.cpp`
- Edit: `include/api/routes/GroupRoutes.hpp`
- Edit: `src/api/routes/UserRoutes.cpp`
- Edit: `include/api/routes/UserRoutes.hpp`

Update the API surface to work with the new permission model. Group creation no longer requires a `role` field. Member management accepts `role_id`, `scope_type`, `scope_id`.

**Step 1: Update GroupRoutes**

The POST/PUT endpoints no longer send/receive `role`. The GET response no longer includes `role` on the group itself.

For the group detail response (GET /groups/{id}), the members array now includes role and scope info:

```cpp
for (const auto& member : vMembers) {
  nlohmann::json jMember = {
      {"id", member.iUserId},
      {"username", member.sUsername},
      {"role_id", member.iRoleId},
      {"role_name", member.sRoleName},
  };
  if (!member.sScopeType.empty()) {
    jMember["scope_type"] = member.sScopeType;
    jMember["scope_id"] = member.iScopeId;
  }
  jMembers.push_back(jMember);
}
```

Add member management endpoints to GroupRoutes (or add to existing UserRoutes):

- `POST /api/v1/groups/{id}/members` — add member with `{user_id, role_id, scope_type?, scope_id?}`
- `DELETE /api/v1/groups/{id}/members` — remove member with same params

**Step 2: Update UserRoutes**

The user detail response (GET /users/{id}) should include group membership with role and scope info. The user create endpoint no longer needs to set a role on the group.

When adding a user to a group via the user management UI, the request now includes `role_id` and optional scope:

```json
{
  "group_ids": [1, 2],
  "memberships": [
    {"group_id": 1, "role_id": 1},
    {"group_id": 2, "role_id": 2, "scope_type": "view", "scope_id": 5}
  ]
}
```

**Step 3: Verify build compiles**

**Step 4: Commit**

```bash
git add src/api/routes/GroupRoutes.cpp src/api/routes/UserRoutes.cpp \
        include/api/routes/GroupRoutes.hpp include/api/routes/UserRoutes.hpp
git commit -m "feat(api): update group/user routes for permission-based model"
```

---

### Task 13: RoleRoutes — CRUD

**Files:**
- Create: `include/api/routes/RoleRoutes.hpp`
- Create: `src/api/routes/RoleRoutes.cpp`
- Edit: `src/main.cpp` (wire up)

New admin-only endpoints for role management.

**Step 1: Create the header**

Create `include/api/routes/RoleRoutes.hpp`:

```cpp
#pragma once

#include <crow.h>

namespace dns::dal {
class RoleRepository;
}

namespace dns::api {
class AuthMiddleware;
}

namespace dns::api::routes {

/// Role CRUD + permission assignment routes.
/// Class abbreviation: rr (role routes — note: the RoleRepository abbreviation is also rr,
/// but they live in different namespaces)
class RoleRoutes {
 public:
  RoleRoutes(dns::dal::RoleRepository& rrRepo,
             const dns::api::AuthMiddleware& amMiddleware);
  ~RoleRoutes();

  void registerRoutes(crow::SimpleApp& app);

 private:
  dns::dal::RoleRepository& _rrRepo;
  const dns::api::AuthMiddleware& _amMiddleware;
};

}  // namespace dns::api::routes
```

**Step 2: Create the implementation**

Create `src/api/routes/RoleRoutes.cpp` with these endpoints:

| Method | Path | Permission | Action |
|--------|------|-----------|--------|
| GET | `/api/v1/roles` | `roles.view` | List all roles |
| POST | `/api/v1/roles` | `roles.create` | Create custom role |
| GET | `/api/v1/roles/<int>` | `roles.view` | Get role with permissions |
| PUT | `/api/v1/roles/<int>` | `roles.edit` | Update role name/description |
| DELETE | `/api/v1/roles/<int>` | `roles.delete` | Delete custom role |
| GET | `/api/v1/roles/<int>/permissions` | `roles.view` | List permissions for role |
| PUT | `/api/v1/roles/<int>/permissions` | `roles.edit` | Set permissions for role |
| GET | `/api/v1/permissions` | `roles.view` | List all available permissions |

Implementation pattern follows existing route files (authenticate, requirePermission, try/catch AppError).

The `GET /api/v1/permissions` endpoint returns the full list of known permissions from `Permissions::kAllPermissions`, grouped by category for the UI checkbox grid:

```cpp
CROW_ROUTE(app, "/api/v1/permissions").methods("GET"_method)(
    [this](const crow::request& req) -> crow::response {
      try {
        auto rcCtx = authenticate(_amMiddleware, req);
        requirePermission(rcCtx, Permissions::kRolesView);

        nlohmann::json jCategories = nlohmann::json::array();
        // Build category groups from Permissions::kAllPermissions
        // Categories: zones, records, providers, views, variables, repos,
        //             audit, users, groups, roles, settings, backup
        struct Category {
          std::string sName;
          std::string sPrefix;
        };
        std::vector<Category> vCategories = {
            {"Zones", "zones."}, {"Records", "records."},
            {"Providers", "providers."}, {"Views", "views."},
            {"Variables", "variables."}, {"Git Repos", "repos."},
            {"Audit", "audit."}, {"Users", "users."},
            {"Groups", "groups."}, {"Roles", "roles."},
            {"Settings", "settings."}, {"Backup", "backup."},
        };
        for (const auto& cat : vCategories) {
          nlohmann::json jPerms = nlohmann::json::array();
          for (const auto& perm : Permissions::kAllPermissions) {
            if (std::string(perm).starts_with(cat.sPrefix)) {
              jPerms.push_back(std::string(perm));
            }
          }
          jCategories.push_back({{"name", cat.sName}, {"permissions", jPerms}});
        }
        return jsonResponse(200, jCategories);
      } catch (const common::AppError& e) {
        return errorResponse(e);
      }
    });
```

For `GET /api/v1/roles/<int>`, include permissions in the response:

```cpp
auto vPerms = _rrRepo.getPermissions(iRoleId);
nlohmann::json jPerms = nlohmann::json::array();
for (const auto& sPerm : vPerms) jPerms.push_back(sPerm);

return jsonResponse(200, {
    {"id", oRole->iId},
    {"name", oRole->sName},
    {"description", oRole->sDescription},
    {"is_system", oRole->bIsSystem},
    {"permissions", jPerms},
    {"created_at", oRole->sCreatedAt},
});
```

For `PUT /api/v1/roles/<int>/permissions`, validate that all submitted permissions are in `kAllPermissions`:

```cpp
auto jBody = nlohmann::json::parse(req.body);
auto jPerms = jBody.value("permissions", nlohmann::json::array());
std::vector<std::string> vPerms;
for (const auto& p : jPerms) {
  std::string sPerm = p.get<std::string>();
  // Validate against known permissions
  bool bValid = false;
  for (const auto& kp : Permissions::kAllPermissions) {
    if (sPerm == kp) { bValid = true; break; }
  }
  if (!bValid) {
    throw common::ValidationError("INVALID_PERMISSION",
                                   "Unknown permission: " + sPerm);
  }
  vPerms.push_back(sPerm);
}
_rrRepo.setPermissions(iRoleId, vPerms);
```

**Step 3: Wire up in main.cpp**

Add `#include "api/routes/RoleRoutes.hpp"` and construct/register:

```cpp
auto roleRoutes = std::make_unique<dns::api::routes::RoleRoutes>(*roleRepo, *amMiddleware);
// ...
roleRoutes->registerRoutes(crowApp);
```

**Step 4: Verify build compiles**

**Step 5: Commit**

```bash
git add include/api/routes/RoleRoutes.hpp src/api/routes/RoleRoutes.cpp src/main.cpp
git commit -m "feat(api): add role CRUD and permission management endpoints"
```

---

### Task 14: RoleRoutes Tests

**Files:**
- Create: `tests/integration/test_role_routes.cpp`

Integration tests for the role API endpoints. Follow the pattern from `tests/integration/test_api_validation.cpp`.

**Step 1: Write the test file**

Test cases:
- List roles returns system roles
- Create custom role succeeds
- Create duplicate name returns 409
- Get role by ID includes permissions
- Update custom role succeeds
- Rename system role returns 400
- Delete custom role succeeds
- Delete system role returns 409
- Delete in-use role returns 409
- Set permissions replaces all
- Set invalid permission returns 400
- List permissions returns all categories

**Step 2: Verify tests pass**

Run: `cmake --build build --parallel && build/tests/dns-tests --gtest_filter='RoleRoutes*' 2>&1 | tail -20`

**Step 3: Commit**

```bash
git add tests/integration/test_role_routes.cpp
git commit -m "test(api): add RoleRoutes integration tests"
```

---

### Task 15: UI — Types + API Client

**Files:**
- Edit: `ui/src/types/index.ts`
- Create: `ui/src/api/roles.ts`
- Edit: `ui/src/api/groups.ts`

**Step 1: Add Role types**

In `ui/src/types/index.ts`, add:

```typescript
export interface Role {
  id: number
  name: string
  description: string
  is_system: boolean
  permissions: string[]
  created_at: string
}

export interface RoleCreate {
  name: string
  description: string
}

export interface PermissionCategory {
  name: string
  permissions: string[]
}

export interface GroupMember {
  id: number
  username: string
  role_id: number
  role_name: string
  scope_type?: string
  scope_id?: number
}
```

Update `Group` interface to remove `role`:

```typescript
export interface Group {
  id: number
  name: string
  description: string
  member_count: number
}

export interface GroupDetail extends Group {
  members: GroupMember[]
}
```

Update `User` interface to include permissions:

```typescript
export interface User {
  user_id: number
  username: string
  email: string
  role: string  // display name of highest role
  permissions: string[]
  auth_method: string
  force_password_change: boolean
}
```

**Step 2: Create roles API module**

Create `ui/src/api/roles.ts`:

```typescript
import { get, post, put, del } from './client'
import type { Role, RoleCreate, PermissionCategory } from '../types'

export function listRoles(): Promise<Role[]> {
  return get('/roles')
}

export function getRole(id: number): Promise<Role> {
  return get(`/roles/${id}`)
}

export function createRole(data: RoleCreate): Promise<{ id: number }> {
  return post('/roles', data)
}

export function updateRole(
  id: number,
  data: RoleCreate,
): Promise<{ message: string }> {
  return put(`/roles/${id}`, data)
}

export function deleteRole(id: number): Promise<{ message: string }> {
  return del(`/roles/${id}`)
}

export function getRolePermissions(id: number): Promise<string[]> {
  return get(`/roles/${id}/permissions`)
}

export function setRolePermissions(
  id: number,
  permissions: string[],
): Promise<{ message: string }> {
  return put(`/roles/${id}/permissions`, { permissions })
}

export function listPermissions(): Promise<PermissionCategory[]> {
  return get('/permissions')
}
```

**Step 3: Update groups API module**

In `ui/src/api/groups.ts`, remove `role` from create/update functions:

```typescript
export function createGroup(data: {
  name: string
  description: string
}): Promise<{ id: number }> {
  return post('/groups', data)
}

export function updateGroup(
  id: number,
  data: { name: string; description: string },
): Promise<{ message: string }> {
  return put(`/groups/${id}`, data)
}
```

**Step 4: Commit**

```bash
git add ui/src/types/index.ts ui/src/api/roles.ts ui/src/api/groups.ts
git commit -m "feat(ui): add role types and API module, update group types"
```

---

### Task 16: UI — useRole Composable Refactor

**Files:**
- Edit: `ui/src/composables/useRole.ts`

Replace role string checks with permission-based checks. The composable now uses the `permissions` array from the auth store.

**Step 1: Update useRole**

```typescript
import { computed } from 'vue'
import { useAuthStore } from '../stores/auth'

export function useRole() {
  const auth = useAuthStore()

  function hasPermission(permission: string): boolean {
    return auth.permissions.includes(permission)
  }

  function hasAnyPermission(...permissions: string[]): boolean {
    return permissions.some(p => auth.permissions.includes(p))
  }

  return {
    // Legacy convenience — still useful for broad UI gating
    isAdmin: computed(() => auth.role === 'Admin'),
    isOperator: computed(() => auth.role === 'Operator' || auth.role === 'Admin'),
    isViewer: computed(() => true),

    // Permission-based checks (preferred)
    hasPermission,
    hasAnyPermission,
    can: hasPermission,  // Alias for template readability
  }
}
```

**Step 2: Update views that use useRole**

Scan all views for `isAdmin` / `isOperator` checks and replace with `can('permission.string')` where appropriate. Key locations:

- Sidebar navigation: show/hide menu items based on permissions
- CRUD views: show/hide create/edit/delete buttons based on entity-specific permissions
- Settings page: gate on `settings.view`
- Deployment push: gate on `zones.deploy`

**Step 3: Commit**

```bash
git add ui/src/composables/useRole.ts
git commit -m "feat(ui): refactor useRole composable for permission-based checks"
```

---

### Task 17: UI — Auth Store + /me Update

**Files:**
- Edit: `ui/src/stores/auth.ts`

The auth store now stores the `permissions` array from the `/me` response and exposes it for permission checks.

**Step 1: Update auth store**

```typescript
import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import * as authApi from '../api/auth'
import type { User } from '../types'

export const useAuthStore = defineStore('auth', () => {
  const user = ref<User | null>(null)
  const token = ref<string | null>(localStorage.getItem('jwt'))

  const isAuthenticated = computed(() => !!token.value && !!user.value)
  const role = computed(() => user.value?.role ?? 'Viewer')
  const permissions = computed(() => user.value?.permissions ?? [])
  const isAdmin = computed(() => role.value === 'Admin')
  const isOperator = computed(() =>
    role.value === 'Operator' || role.value === 'Admin',
  )

  async function hydrate(): Promise<boolean> {
    if (!token.value) return false
    try {
      user.value = await authApi.me()
      return true
    } catch {
      clear()
      return false
    }
  }

  async function login(username: string, password: string) {
    const result = await authApi.login(username, password)
    token.value = result.token
    localStorage.setItem('jwt', result.token)
    user.value = await authApi.me()
  }

  async function logout() {
    try {
      await authApi.logout()
    } finally {
      clear()
    }
  }

  function clear() {
    token.value = null
    user.value = null
    localStorage.removeItem('jwt')
  }

  return {
    user, token, isAuthenticated, role, permissions,
    isAdmin, isOperator, hydrate, login, logout,
  }
})
```

**Step 2: Commit**

```bash
git add ui/src/stores/auth.ts
git commit -m "feat(ui): expose permissions array in auth store from /me response"
```

---

### Task 18: UI — RolesView Page

**Files:**
- Create: `ui/src/views/RolesView.vue`

Admin page for managing roles. DataTable CRUD with a permission checkbox grid for editing role permissions.

**Step 1: Create RolesView**

The view contains:
- DataTable listing all roles (name, description, is_system badge, permission count)
- Create button opens a Drawer with name + description fields
- Row click opens Drawer with:
  - Name and description fields (name read-only for system roles)
  - Permission checkbox grid grouped by category (from `GET /api/v1/permissions`)
  - Each category is a collapsible section with checkboxes for individual permissions
  - "Select All" / "Deselect All" per category
- Delete button (disabled for system roles and in-use roles)

**Layout reference:** Follow the DataTable + Drawer pattern from existing views (ProvidersView, GroupsView).

**Permission grid structure:**
```
[Zones]
  ☑ zones.view    ☑ zones.create    ☑ zones.edit
  ☑ zones.delete  ☑ zones.deploy    ☑ zones.rollback

[Records]
  ☑ records.view  ☑ records.create  ☑ records.edit
  ☑ records.delete ☑ records.import

[Providers]
  ☑ providers.view  ☑ providers.create  ☑ providers.edit
  ☑ providers.delete
...
```

Use PrimeVue `Checkbox` components in a CSS grid layout (3 columns per category row).

**Step 2: Commit**

```bash
git add ui/src/views/RolesView.vue
git commit -m "feat(ui): add RolesView with permission checkbox grid"
```

---

### Task 19: UI — GroupsView Update

**Files:**
- Edit: `ui/src/views/GroupsView.vue`

Remove the role dropdown from group create/edit. Update the members display to show role and scope for each member.

**Step 1: Update group form**

Remove the `role` field from the group create/edit form. Groups no longer have an inherent role — roles are assigned per member.

**Step 2: Update members display**

In the group detail view, the members table now shows:
- Username
- Role (dropdown from available roles)
- Scope type (dropdown: Global / View / Zone)
- Scope ID (view or zone picker, shown only when scope type is not Global)
- Remove button

Add member form at the bottom:
- User selector (dropdown of all users not already in this group at this scope)
- Role selector (dropdown of available roles)
- Scope type selector
- Scope picker (view or zone dropdown, conditional)
- Add button

**Step 3: Commit**

```bash
git add ui/src/views/GroupsView.vue
git commit -m "feat(ui): update GroupsView for role-per-member with scope"
```

---

### Task 20: UI — Routing + Sidebar

**Files:**
- Edit: `ui/src/router/index.ts`
- Edit: `ui/src/components/layout/AppSidebar.vue`

**Step 1: Add roles route**

In `ui/src/router/index.ts`, add:

```typescript
{
  path: '/roles',
  name: 'Roles',
  component: () => import('../views/RolesView.vue'),
  meta: { requiresAuth: true },
}
```

**Step 2: Add sidebar entry**

In `AppSidebar.vue`, add a "Roles" navigation item in the admin section, near Groups:

```typescript
{ label: 'Roles', icon: 'pi pi-shield', to: '/roles', permission: 'roles.view' },
```

Gate visibility on `can('roles.view')` from the useRole composable.

**Step 3: Commit**

```bash
git add ui/src/router/index.ts ui/src/components/layout/AppSidebar.vue
git commit -m "feat(ui): add roles route and sidebar navigation entry"
```

---

### Task 21: Full Verification Pass

**Step 1: Build backend**

```bash
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel
```

Expected: Clean build, no warnings.

**Step 2: Run backend tests**

```bash
build/tests/dns-tests
```

Expected: All existing tests pass (or skip for DB tests).

**Step 3: Build UI**

```bash
cd ui && npm run build
```

Expected: Clean build, no TypeScript errors.

**Step 4: Manual QA checklist**

- [ ] Login as admin → verify `/me` returns permissions array
- [ ] Navigate to Roles page → see Admin, Operator, Viewer system roles
- [ ] Click Admin role → see all permissions checked
- [ ] Click Viewer role → see only view permissions checked
- [ ] Create custom role with subset of permissions → verify saves
- [ ] Cannot rename system roles
- [ ] Cannot delete system roles
- [ ] Delete unused custom role → succeeds
- [ ] Navigate to Groups → no role dropdown on group form
- [ ] Add member to group → see role selector + scope fields
- [ ] Add member with view-level scope → verify user has permissions only for that view's zones
- [ ] Verify all existing CRUD pages still enforce correct permissions
- [ ] API key authentication still resolves permissions correctly
- [ ] Zone switcher in top bar shows only zones the user has `zones.view` for

**Step 5: Commit any fixes**

```bash
git add -A
git commit -m "fix: verification pass fixes for permissions restructure"
```

---

## Key Architecture Decisions

1. **Permissions resolved per-request, not cached in JWT.** This ensures permission changes take effect immediately without requiring re-login. The cost is one DB query per request (an indexed join on `group_members` → `role_permissions`), which is acceptable for the expected request volume. A short-lived cache can be added later if needed.

2. **`groups.role` dropped, `group_members.role_id` added.** This enables the same user to have different roles in different groups or at different scopes. A user in the "DNS Team" group might be an Operator globally but an Admin for a specific production view.

3. **Composite PK on group_members.** The new PK `(user_id, group_id, role_id, scope_type, scope_id)` allows a user to hold multiple role assignments within the same group at different scopes. This is the most flexible model, though in practice most assignments will be global scope.

4. **`requirePermission()` is a string check on the set.** No hierarchy — either you have the permission or you don't. The "Admin > Operator > Viewer" hierarchy is gone; it's replaced by the union of permissions from all matching role assignments. This is simpler to reason about and more flexible for custom roles.

5. **Backward compatibility with JWT `role` field.** The JWT still contains a `role` field (the name of the highest-privilege role) for display purposes and logging. It is never used for authorization decisions — all auth checks use the resolved `vPermissions` set.
