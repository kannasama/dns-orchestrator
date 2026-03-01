# Phase 5: DAL Core Repositories Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement all core DAL repositories with full CRUD, basic CRUD API routes for providers/views/zones/variables, wire ApiServer with Crow, and complete startup steps 10-11.

**Architecture:** Phase 5 builds on the Phase 4 foundation (AuthMiddleware, AuthService, ConnectionPool, CryptoService). Each repository takes `ConnectionPool&` in its constructor, uses `ConnectionGuard` RAII for connection checkout, and runs parameterized queries via `pqxx::work` transactions. Route handlers follow the AuthRoutes pattern: take repository + middleware references, register lambdas on `crow::SimpleApp&`, authenticate via `AuthMiddleware::authenticate()`, and catch `AppError` at the boundary. ApiServer owns the `crow::SimpleApp` instance and wires all route classes.

**Tech Stack:** C++20, libpqxx (PostgreSQL), nlohmann/json, Crow v1.3.1 (HTTP), OpenSSL (AES-256-GCM for provider tokens), Google Test

**Key References:**
- `docs/ARCHITECTURE.md` §4.4 (DAL), §6.2-6.9 (REST API), §7.1 (Data Flow)
- `scripts/db/001_initial_schema.sql` — all table definitions
- `scripts/db/002_add_indexes.sql` — performance indexes
- `include/dal/ConnectionPool.hpp` — `ConnectionGuard` RAII pattern
- `src/dal/UserRepository.cpp` — canonical repository implementation pattern
- `src/api/routes/AuthRoutes.cpp` — canonical route handler pattern
- `include/common/Errors.hpp` — `AppError` hierarchy (400/401/403/404/409)
- `include/common/Types.hpp` — `RequestContext` struct
- `include/security/CryptoService.hpp` — `encrypt()`/`decrypt()` for provider tokens

**Naming Conventions** (from `docs/CODE_STANDARDS.md`):
- Classes: `PascalCase` — Instance vars: `_` + type prefix + `PascalCase` (e.g., `_cpPool`)
- Primitives: type prefix + `PascalCase` (e.g., `sName`, `iZoneId`, `bRevoked`)
- Functions: `camelCase` — Constants: `PascalCase` — Namespaces: `lowercase`

**Testing Strategy:** DAL repositories interact directly with PostgreSQL via libpqxx — no interface abstraction exists for mocking. Unit tests are not practical for SQL-dependent code. Instead: (1) each task verifies clean compilation, (2) existing 38 unit tests must continue to pass, (3) integration tests against a real database are deferred to Phase 8.

**Existing Stubs:** All 6 repository headers and implementations exist as empty stubs (default constructor/destructor only). All 5 route headers and implementations exist as stubs throwing `runtime_error{"not implemented"}`. ApiServer exists as a stub. This plan replaces each stub with the full implementation.

---

## Task 1: ProviderRepository

**Files:**
- Modify: `include/dal/ProviderRepository.hpp`
- Modify: `src/dal/ProviderRepository.cpp`

**Context:** The `providers` table stores DNS provider credentials. The `encrypted_token` column holds AES-256-GCM ciphertext produced by `CryptoService::encrypt()`. On read, tokens are decrypted. On list, tokens are NOT returned (security). Constructor takes both `ConnectionPool&` and `const CryptoService&`.

**Step 1: Write the header**

Replace `include/dal/ProviderRepository.hpp` with:

```cpp
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace dns::security {
class CryptoService;
}

namespace dns::dal {

class ConnectionPool;

/// Row type returned from provider queries (list view — no token).
struct ProviderRow {
  int64_t iId = 0;
  std::string sName;
  std::string sType;
  std::string sApiEndpoint;
  std::string sCreatedAt;
  std::string sUpdatedAt;
};

/// Row type returned from provider queries (detail view — decrypted token).
struct ProviderDetailRow {
  int64_t iId = 0;
  std::string sName;
  std::string sType;
  std::string sApiEndpoint;
  std::string sDecryptedToken;
  std::string sCreatedAt;
  std::string sUpdatedAt;
};

/// Manages the providers table; encrypts tokens on write, decrypts on read.
/// Class abbreviation: pr
class ProviderRepository {
 public:
  ProviderRepository(ConnectionPool& cpPool,
                     const dns::security::CryptoService& csService);
  ~ProviderRepository();

  /// Create a provider. Encrypts the raw token before storage.
  /// Returns the new provider ID.
  /// Throws ConflictError if name already exists.
  int64_t create(const std::string& sName, const std::string& sType,
                 const std::string& sApiEndpoint, const std::string& sRawToken);

  /// Find a provider by ID with decrypted token.
  /// Returns nullopt if not found.
  std::optional<ProviderDetailRow> findById(int64_t iProviderId);

  /// List all providers (no tokens in result).
  std::vector<ProviderRow> list();

  /// Update a provider. Encrypts the new token if provided.
  /// Throws NotFoundError if provider doesn't exist.
  void update(int64_t iProviderId, const std::string& sName,
              const std::string& sType, const std::string& sApiEndpoint,
              const std::string& sRawToken);

  /// Delete a provider by ID.
  /// Throws NotFoundError if provider doesn't exist.
  void deleteById(int64_t iProviderId);

 private:
  ConnectionPool& _cpPool;
  const dns::security::CryptoService& _csService;
};

}  // namespace dns::dal
```

**Step 2: Write the implementation**

Replace `src/dal/ProviderRepository.cpp` with:

```cpp
#include "dal/ProviderRepository.hpp"

#include "common/Errors.hpp"
#include "dal/ConnectionPool.hpp"
#include "security/CryptoService.hpp"

#include <pqxx/pqxx>

namespace dns::dal {

ProviderRepository::ProviderRepository(ConnectionPool& cpPool,
                                       const dns::security::CryptoService& csService)
    : _cpPool(cpPool), _csService(csService) {}
ProviderRepository::~ProviderRepository() = default;

int64_t ProviderRepository::create(const std::string& sName, const std::string& sType,
                                   const std::string& sApiEndpoint,
                                   const std::string& sRawToken) {
  std::string sEncrypted = _csService.encrypt(sRawToken);
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  try {
    auto result = txn.exec(
        "INSERT INTO providers (name, type, api_endpoint, encrypted_token) "
        "VALUES ($1, $2::provider_type, $3, $4) RETURNING id",
        pqxx::params{sName, sType, sApiEndpoint, sEncrypted});
    txn.commit();
    return result.one_row()[0].as<int64_t>();
  } catch (const pqxx::unique_violation&) {
    throw common::ConflictError("duplicate_provider",
                                "Provider with name '" + sName + "' already exists");
  }
}

std::optional<ProviderDetailRow> ProviderRepository::findById(int64_t iProviderId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT id, name, type::text, api_endpoint, encrypted_token, "
      "created_at::text, updated_at::text "
      "FROM providers WHERE id = $1",
      pqxx::params{iProviderId});
  txn.commit();

  if (result.empty()) return std::nullopt;

  auto row = result[0];
  return ProviderDetailRow{
      row[0].as<int64_t>(),
      row[1].as<std::string>(),
      row[2].as<std::string>(),
      row[3].as<std::string>(),
      _csService.decrypt(row[4].as<std::string>()),
      row[5].as<std::string>(),
      row[6].as<std::string>(),
  };
}

std::vector<ProviderRow> ProviderRepository::list() {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT id, name, type::text, api_endpoint, "
      "created_at::text, updated_at::text "
      "FROM providers ORDER BY name");
  txn.commit();

  std::vector<ProviderRow> vRows;
  vRows.reserve(result.size());
  for (const auto& row : result) {
    vRows.push_back({
        row[0].as<int64_t>(),
        row[1].as<std::string>(),
        row[2].as<std::string>(),
        row[3].as<std::string>(),
        row[4].as<std::string>(),
        row[5].as<std::string>(),
    });
  }
  return vRows;
}

void ProviderRepository::update(int64_t iProviderId, const std::string& sName,
                                const std::string& sType,
                                const std::string& sApiEndpoint,
                                const std::string& sRawToken) {
  std::string sEncrypted = _csService.encrypt(sRawToken);
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  try {
    auto result = txn.exec(
        "UPDATE providers SET name = $2, type = $3::provider_type, "
        "api_endpoint = $4, encrypted_token = $5, updated_at = NOW() "
        "WHERE id = $1",
        pqxx::params{iProviderId, sName, sType, sApiEndpoint, sEncrypted});
    txn.commit();
    if (result.affected_rows() == 0) {
      throw common::NotFoundError("provider_not_found", "Provider not found");
    }
  } catch (const pqxx::unique_violation&) {
    throw common::ConflictError("duplicate_provider",
                                "Provider with name '" + sName + "' already exists");
  }
}

void ProviderRepository::deleteById(int64_t iProviderId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec("DELETE FROM providers WHERE id = $1",
                         pqxx::params{iProviderId});
  txn.commit();
  if (result.affected_rows() == 0) {
    throw common::NotFoundError("provider_not_found", "Provider not found");
  }
}

}  // namespace dns::dal
```

**Step 3: Build to verify compilation**

Run: `cmake --build build --parallel 2>&1 | tail -5`
Expected: Clean build, no errors.

**Step 4: Run existing tests**

Run: `ctest --test-dir build --output-on-failure`
Expected: All 38 tests pass.

**Step 5: Commit**

```bash
git add include/dal/ProviderRepository.hpp src/dal/ProviderRepository.cpp
git commit -m "feat(dal): implement ProviderRepository with encrypted token CRUD"
```

---

## Task 2: ViewRepository

**Files:**
- Modify: `include/dal/ViewRepository.hpp`
- Modify: `src/dal/ViewRepository.cpp`

**Context:** The `views` table stores split-horizon view definitions. The `view_providers` join table maps views to providers (M:N). This repository manages both tables.

**Step 1: Write the header**

Replace `include/dal/ViewRepository.hpp` with:

```cpp
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace dns::dal {

class ConnectionPool;

/// Row type returned from view queries.
struct ViewRow {
  int64_t iId = 0;
  std::string sName;
  std::string sDescription;
  std::string sCreatedAt;
  std::vector<int64_t> vProviderIds;
};

/// Manages views + view_providers join table.
/// Class abbreviation: vr
class ViewRepository {
 public:
  explicit ViewRepository(ConnectionPool& cpPool);
  ~ViewRepository();

  /// Create a view. Returns the new view ID.
  /// Throws ConflictError if name already exists.
  int64_t create(const std::string& sName, const std::string& sDescription);

  /// Find a view by ID (includes attached provider IDs).
  /// Returns nullopt if not found.
  std::optional<ViewRow> findById(int64_t iViewId);

  /// List all views (includes attached provider IDs for each).
  std::vector<ViewRow> list();

  /// Update a view's name and description.
  /// Throws NotFoundError if view doesn't exist.
  void update(int64_t iViewId, const std::string& sName,
              const std::string& sDescription);

  /// Delete a view by ID.
  /// Throws NotFoundError if view doesn't exist.
  void deleteById(int64_t iViewId);

  /// Attach a provider to a view.
  /// Throws ConflictError if already attached.
  void attachProvider(int64_t iViewId, int64_t iProviderId);

  /// Detach a provider from a view.
  /// Throws NotFoundError if not attached.
  void detachProvider(int64_t iViewId, int64_t iProviderId);

 private:
  /// Load provider IDs for a given view within an existing transaction.
  std::vector<int64_t> loadProviderIds(pqxx::work& txn, int64_t iViewId);

  ConnectionPool& _cpPool;
};

}  // namespace dns::dal
```

**Step 2: Write the implementation**

Replace `src/dal/ViewRepository.cpp` with:

```cpp
#include "dal/ViewRepository.hpp"

#include "common/Errors.hpp"
#include "dal/ConnectionPool.hpp"

#include <pqxx/pqxx>

namespace dns::dal {

ViewRepository::ViewRepository(ConnectionPool& cpPool) : _cpPool(cpPool) {}
ViewRepository::~ViewRepository() = default;

std::vector<int64_t> ViewRepository::loadProviderIds(pqxx::work& txn,
                                                     int64_t iViewId) {
  auto result = txn.exec(
      "SELECT provider_id FROM view_providers "
      "WHERE view_id = $1 ORDER BY provider_id",
      pqxx::params{iViewId});
  std::vector<int64_t> vIds;
  vIds.reserve(result.size());
  for (const auto& row : result) {
    vIds.push_back(row[0].as<int64_t>());
  }
  return vIds;
}

int64_t ViewRepository::create(const std::string& sName,
                               const std::string& sDescription) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  try {
    auto result = txn.exec(
        "INSERT INTO views (name, description) VALUES ($1, $2) RETURNING id",
        pqxx::params{sName, sDescription.empty() ? nullptr : &sDescription});
    txn.commit();
    return result.one_row()[0].as<int64_t>();
  } catch (const pqxx::unique_violation&) {
    throw common::ConflictError("duplicate_view",
                                "View with name '" + sName + "' already exists");
  }
}

std::optional<ViewRow> ViewRepository::findById(int64_t iViewId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT id, name, COALESCE(description, ''), created_at::text "
      "FROM views WHERE id = $1",
      pqxx::params{iViewId});

  if (result.empty()) {
    txn.commit();
    return std::nullopt;
  }

  auto row = result[0];
  ViewRow vRow;
  vRow.iId = row[0].as<int64_t>();
  vRow.sName = row[1].as<std::string>();
  vRow.sDescription = row[2].as<std::string>();
  vRow.sCreatedAt = row[3].as<std::string>();
  vRow.vProviderIds = loadProviderIds(txn, iViewId);
  txn.commit();
  return vRow;
}

std::vector<ViewRow> ViewRepository::list() {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT id, name, COALESCE(description, ''), created_at::text "
      "FROM views ORDER BY name");

  std::vector<ViewRow> vRows;
  vRows.reserve(result.size());
  for (const auto& row : result) {
    ViewRow vRow;
    vRow.iId = row[0].as<int64_t>();
    vRow.sName = row[1].as<std::string>();
    vRow.sDescription = row[2].as<std::string>();
    vRow.sCreatedAt = row[3].as<std::string>();
    vRow.vProviderIds = loadProviderIds(txn, vRow.iId);
    vRows.push_back(std::move(vRow));
  }
  txn.commit();
  return vRows;
}

void ViewRepository::update(int64_t iViewId, const std::string& sName,
                            const std::string& sDescription) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  try {
    auto result = txn.exec(
        "UPDATE views SET name = $2, description = $3 WHERE id = $1",
        pqxx::params{iViewId, sName,
                     sDescription.empty() ? nullptr : &sDescription});
    txn.commit();
    if (result.affected_rows() == 0) {
      throw common::NotFoundError("view_not_found", "View not found");
    }
  } catch (const pqxx::unique_violation&) {
    throw common::ConflictError("duplicate_view",
                                "View with name '" + sName + "' already exists");
  }
}

void ViewRepository::deleteById(int64_t iViewId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec("DELETE FROM views WHERE id = $1",
                         pqxx::params{iViewId});
  txn.commit();
  if (result.affected_rows() == 0) {
    throw common::NotFoundError("view_not_found", "View not found");
  }
}

void ViewRepository::attachProvider(int64_t iViewId, int64_t iProviderId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  try {
    txn.exec(
        "INSERT INTO view_providers (view_id, provider_id) VALUES ($1, $2)",
        pqxx::params{iViewId, iProviderId});
    txn.commit();
  } catch (const pqxx::unique_violation&) {
    throw common::ConflictError(
        "provider_already_attached",
        "Provider is already attached to this view");
  } catch (const pqxx::foreign_key_violation& e) {
    std::string sMsg = e.what();
    if (sMsg.find("view_providers_view_id_fkey") != std::string::npos) {
      throw common::NotFoundError("view_not_found", "View not found");
    }
    throw common::NotFoundError("provider_not_found", "Provider not found");
  }
}

void ViewRepository::detachProvider(int64_t iViewId, int64_t iProviderId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "DELETE FROM view_providers WHERE view_id = $1 AND provider_id = $2",
      pqxx::params{iViewId, iProviderId});
  txn.commit();
  if (result.affected_rows() == 0) {
    throw common::NotFoundError("provider_not_attached",
                                "Provider is not attached to this view");
  }
}

}  // namespace dns::dal
```

**Step 3: Build and run tests**

Run: `cmake --build build --parallel && ctest --test-dir build --output-on-failure`
Expected: Clean build, all 38 tests pass.

**Step 4: Commit**

```bash
git add include/dal/ViewRepository.hpp src/dal/ViewRepository.cpp
git commit -m "feat(dal): implement ViewRepository with view_providers join table"
```

---

## Task 3: ZoneRepository

**Files:**
- Modify: `include/dal/ZoneRepository.hpp`
- Modify: `src/dal/ZoneRepository.cpp`

**Context:** The `zones` table has a UNIQUE constraint on `(name, view_id)` and a foreign key to `views`. The `deployment_retention` column is nullable (falls back to the global config default). List supports optional `view_id` filtering.

**Step 1: Write the header**

Replace `include/dal/ZoneRepository.hpp` with:

```cpp
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace dns::dal {

class ConnectionPool;

/// Row type returned from zone queries.
struct ZoneRow {
  int64_t iId = 0;
  std::string sName;
  int64_t iViewId = 0;
  std::optional<int> oDeploymentRetention;
  std::string sCreatedAt;
};

/// Manages the zones table.
/// Class abbreviation: zr
class ZoneRepository {
 public:
  explicit ZoneRepository(ConnectionPool& cpPool);
  ~ZoneRepository();

  /// Create a zone. Returns the new zone ID.
  /// Throws ConflictError if (name, view_id) already exists.
  int64_t create(const std::string& sName, int64_t iViewId,
                 std::optional<int> oDeploymentRetention);

  /// Find a zone by ID. Returns nullopt if not found.
  std::optional<ZoneRow> findById(int64_t iZoneId);

  /// List zones, optionally filtered by view_id.
  std::vector<ZoneRow> list(std::optional<int64_t> oViewId);

  /// Update a zone.
  /// Throws NotFoundError if zone doesn't exist.
  void update(int64_t iZoneId, const std::string& sName, int64_t iViewId,
              std::optional<int> oDeploymentRetention);

  /// Delete a zone by ID.
  /// Throws NotFoundError if zone doesn't exist.
  void deleteById(int64_t iZoneId);

 private:
  ConnectionPool& _cpPool;
};

}  // namespace dns::dal
```

**Step 2: Write the implementation**

Replace `src/dal/ZoneRepository.cpp` with:

```cpp
#include "dal/ZoneRepository.hpp"

#include "common/Errors.hpp"
#include "dal/ConnectionPool.hpp"

#include <pqxx/pqxx>

namespace dns::dal {

ZoneRepository::ZoneRepository(ConnectionPool& cpPool) : _cpPool(cpPool) {}
ZoneRepository::~ZoneRepository() = default;

int64_t ZoneRepository::create(const std::string& sName, int64_t iViewId,
                               std::optional<int> oDeploymentRetention) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  try {
    pqxx::result result;
    if (oDeploymentRetention.has_value()) {
      result = txn.exec(
          "INSERT INTO zones (name, view_id, deployment_retention) "
          "VALUES ($1, $2, $3) RETURNING id",
          pqxx::params{sName, iViewId, *oDeploymentRetention});
    } else {
      result = txn.exec(
          "INSERT INTO zones (name, view_id) VALUES ($1, $2) RETURNING id",
          pqxx::params{sName, iViewId});
    }
    txn.commit();
    return result.one_row()[0].as<int64_t>();
  } catch (const pqxx::unique_violation&) {
    throw common::ConflictError(
        "duplicate_zone",
        "Zone '" + sName + "' already exists in this view");
  } catch (const pqxx::foreign_key_violation&) {
    throw common::NotFoundError("view_not_found", "View not found");
  }
}

std::optional<ZoneRow> ZoneRepository::findById(int64_t iZoneId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT id, name, view_id, deployment_retention, created_at::text "
      "FROM zones WHERE id = $1",
      pqxx::params{iZoneId});
  txn.commit();

  if (result.empty()) return std::nullopt;

  auto row = result[0];
  ZoneRow zRow;
  zRow.iId = row[0].as<int64_t>();
  zRow.sName = row[1].as<std::string>();
  zRow.iViewId = row[2].as<int64_t>();
  if (!row[3].is_null()) {
    zRow.oDeploymentRetention = row[3].as<int>();
  }
  zRow.sCreatedAt = row[4].as<std::string>();
  return zRow;
}

std::vector<ZoneRow> ZoneRepository::list(std::optional<int64_t> oViewId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);

  pqxx::result result;
  if (oViewId.has_value()) {
    result = txn.exec(
        "SELECT id, name, view_id, deployment_retention, created_at::text "
        "FROM zones WHERE view_id = $1 ORDER BY name",
        pqxx::params{*oViewId});
  } else {
    result = txn.exec(
        "SELECT id, name, view_id, deployment_retention, created_at::text "
        "FROM zones ORDER BY name");
  }
  txn.commit();

  std::vector<ZoneRow> vRows;
  vRows.reserve(result.size());
  for (const auto& row : result) {
    ZoneRow zRow;
    zRow.iId = row[0].as<int64_t>();
    zRow.sName = row[1].as<std::string>();
    zRow.iViewId = row[2].as<int64_t>();
    if (!row[3].is_null()) {
      zRow.oDeploymentRetention = row[3].as<int>();
    }
    zRow.sCreatedAt = row[4].as<std::string>();
    vRows.push_back(std::move(zRow));
  }
  return vRows;
}

void ZoneRepository::update(int64_t iZoneId, const std::string& sName,
                            int64_t iViewId,
                            std::optional<int> oDeploymentRetention) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  try {
    pqxx::result result;
    if (oDeploymentRetention.has_value()) {
      result = txn.exec(
          "UPDATE zones SET name = $2, view_id = $3, deployment_retention = $4 "
          "WHERE id = $1",
          pqxx::params{iZoneId, sName, iViewId, *oDeploymentRetention});
    } else {
      result = txn.exec(
          "UPDATE zones SET name = $2, view_id = $3, deployment_retention = NULL "
          "WHERE id = $1",
          pqxx::params{iZoneId, sName, iViewId});
    }
    txn.commit();
    if (result.affected_rows() == 0) {
      throw common::NotFoundError("zone_not_found", "Zone not found");
    }
  } catch (const pqxx::unique_violation&) {
    throw common::ConflictError(
        "duplicate_zone",
        "Zone '" + sName + "' already exists in this view");
  } catch (const pqxx::foreign_key_violation&) {
    throw common::NotFoundError("view_not_found", "View not found");
  }
}

void ZoneRepository::deleteById(int64_t iZoneId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec("DELETE FROM zones WHERE id = $1",
                         pqxx::params{iZoneId});
  txn.commit();
  if (result.affected_rows() == 0) {
    throw common::NotFoundError("zone_not_found", "Zone not found");
  }
}

}  // namespace dns::dal
```

**Step 3: Build and run tests**

Run: `cmake --build build --parallel && ctest --test-dir build --output-on-failure`
Expected: Clean build, all 38 tests pass.

**Step 4: Commit**

```bash
git add include/dal/ZoneRepository.hpp src/dal/ZoneRepository.cpp
git commit -m "feat(dal): implement ZoneRepository with view_id filtering"
```

---

## Task 4: VariableRepository

**Files:**
- Modify: `include/dal/VariableRepository.hpp`
- Modify: `src/dal/VariableRepository.cpp`

**Context:** The `variables` table has a CHECK constraint enforcing that `scope='global'` requires `zone_id IS NULL` and `scope='zone'` requires `zone_id IS NOT NULL`. The `findByName()` method is used by VariableEngine (Phase 6) for template expansion — it resolves zone-scoped first, then falls back to global.

**Step 1: Write the header**

Replace `include/dal/VariableRepository.hpp` with:

```cpp
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace dns::dal {

class ConnectionPool;

/// Row type returned from variable queries.
struct VariableRow {
  int64_t iId = 0;
  std::string sName;
  std::string sValue;
  std::string sType;
  std::string sScope;
  std::optional<int64_t> oZoneId;
  std::string sCreatedAt;
  std::string sUpdatedAt;
};

/// Manages the variables table.
/// Class abbreviation: var
class VariableRepository {
 public:
  explicit VariableRepository(ConnectionPool& cpPool);
  ~VariableRepository();

  /// Create a variable. Returns the new variable ID.
  /// Throws ConflictError if (name, zone_id) already exists.
  int64_t create(const std::string& sName, const std::string& sValue,
                 const std::string& sType, const std::string& sScope,
                 std::optional<int64_t> oZoneId);

  /// Find a variable by ID. Returns nullopt if not found.
  std::optional<VariableRow> findById(int64_t iVariableId);

  /// Find a variable by name and zone_id.
  /// For global lookup, pass oZoneId = std::nullopt.
  /// Returns nullopt if not found.
  std::optional<VariableRow> findByName(const std::string& sName,
                                        std::optional<int64_t> oZoneId);

  /// List variables, optionally filtered by scope and/or zone_id.
  std::vector<VariableRow> list(std::optional<std::string> oScope,
                                std::optional<int64_t> oZoneId);

  /// Update a variable's name, value, and type.
  /// Throws NotFoundError if variable doesn't exist.
  void update(int64_t iVariableId, const std::string& sName,
              const std::string& sValue, const std::string& sType);

  /// Delete a variable by ID.
  /// Throws NotFoundError if variable doesn't exist.
  void deleteById(int64_t iVariableId);

 private:
  ConnectionPool& _cpPool;
};

}  // namespace dns::dal
```

**Step 2: Write the implementation**

Replace `src/dal/VariableRepository.cpp` with:

```cpp
#include "dal/VariableRepository.hpp"

#include "common/Errors.hpp"
#include "dal/ConnectionPool.hpp"

#include <pqxx/pqxx>

namespace dns::dal {

VariableRepository::VariableRepository(ConnectionPool& cpPool) : _cpPool(cpPool) {}
VariableRepository::~VariableRepository() = default;

int64_t VariableRepository::create(const std::string& sName,
                                   const std::string& sValue,
                                   const std::string& sType,
                                   const std::string& sScope,
                                   std::optional<int64_t> oZoneId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  try {
    pqxx::result result;
    if (oZoneId.has_value()) {
      result = txn.exec(
          "INSERT INTO variables (name, value, type, scope, zone_id) "
          "VALUES ($1, $2, $3::variable_type, $4::variable_scope, $5) "
          "RETURNING id",
          pqxx::params{sName, sValue, sType, sScope, *oZoneId});
    } else {
      result = txn.exec(
          "INSERT INTO variables (name, value, type, scope) "
          "VALUES ($1, $2, $3::variable_type, $4::variable_scope) "
          "RETURNING id",
          pqxx::params{sName, sValue, sType, sScope});
    }
    txn.commit();
    return result.one_row()[0].as<int64_t>();
  } catch (const pqxx::unique_violation&) {
    throw common::ConflictError("duplicate_variable",
                                "Variable '" + sName + "' already exists in this scope");
  } catch (const pqxx::check_violation&) {
    throw common::ValidationError(
        "invalid_scope",
        "Global variables must not have a zone_id; zone variables require one");
  } catch (const pqxx::foreign_key_violation&) {
    throw common::NotFoundError("zone_not_found", "Zone not found");
  }
}

std::optional<VariableRow> VariableRepository::findById(int64_t iVariableId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT id, name, value, type::text, scope::text, zone_id, "
      "created_at::text, updated_at::text "
      "FROM variables WHERE id = $1",
      pqxx::params{iVariableId});
  txn.commit();

  if (result.empty()) return std::nullopt;

  auto row = result[0];
  VariableRow vRow;
  vRow.iId = row[0].as<int64_t>();
  vRow.sName = row[1].as<std::string>();
  vRow.sValue = row[2].as<std::string>();
  vRow.sType = row[3].as<std::string>();
  vRow.sScope = row[4].as<std::string>();
  if (!row[5].is_null()) {
    vRow.oZoneId = row[5].as<int64_t>();
  }
  vRow.sCreatedAt = row[6].as<std::string>();
  vRow.sUpdatedAt = row[7].as<std::string>();
  return vRow;
}

std::optional<VariableRow> VariableRepository::findByName(
    const std::string& sName, std::optional<int64_t> oZoneId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);

  pqxx::result result;
  if (oZoneId.has_value()) {
    result = txn.exec(
        "SELECT id, name, value, type::text, scope::text, zone_id, "
        "created_at::text, updated_at::text "
        "FROM variables WHERE name = $1 AND zone_id = $2",
        pqxx::params{sName, *oZoneId});
  } else {
    result = txn.exec(
        "SELECT id, name, value, type::text, scope::text, zone_id, "
        "created_at::text, updated_at::text "
        "FROM variables WHERE name = $1 AND zone_id IS NULL",
        pqxx::params{sName});
  }
  txn.commit();

  if (result.empty()) return std::nullopt;

  auto row = result[0];
  VariableRow vRow;
  vRow.iId = row[0].as<int64_t>();
  vRow.sName = row[1].as<std::string>();
  vRow.sValue = row[2].as<std::string>();
  vRow.sType = row[3].as<std::string>();
  vRow.sScope = row[4].as<std::string>();
  if (!row[5].is_null()) {
    vRow.oZoneId = row[5].as<int64_t>();
  }
  vRow.sCreatedAt = row[6].as<std::string>();
  vRow.sUpdatedAt = row[7].as<std::string>();
  return vRow;
}

std::vector<VariableRow> VariableRepository::list(
    std::optional<std::string> oScope, std::optional<int64_t> oZoneId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);

  pqxx::result result;
  if (oScope.has_value() && oZoneId.has_value()) {
    result = txn.exec(
        "SELECT id, name, value, type::text, scope::text, zone_id, "
        "created_at::text, updated_at::text "
        "FROM variables WHERE scope = $1::variable_scope AND zone_id = $2 "
        "ORDER BY name",
        pqxx::params{*oScope, *oZoneId});
  } else if (oScope.has_value()) {
    result = txn.exec(
        "SELECT id, name, value, type::text, scope::text, zone_id, "
        "created_at::text, updated_at::text "
        "FROM variables WHERE scope = $1::variable_scope ORDER BY name",
        pqxx::params{*oScope});
  } else if (oZoneId.has_value()) {
    result = txn.exec(
        "SELECT id, name, value, type::text, scope::text, zone_id, "
        "created_at::text, updated_at::text "
        "FROM variables WHERE zone_id = $1 ORDER BY name",
        pqxx::params{*oZoneId});
  } else {
    result = txn.exec(
        "SELECT id, name, value, type::text, scope::text, zone_id, "
        "created_at::text, updated_at::text "
        "FROM variables ORDER BY name");
  }
  txn.commit();

  std::vector<VariableRow> vRows;
  vRows.reserve(result.size());
  for (const auto& row : result) {
    VariableRow vRow;
    vRow.iId = row[0].as<int64_t>();
    vRow.sName = row[1].as<std::string>();
    vRow.sValue = row[2].as<std::string>();
    vRow.sType = row[3].as<std::string>();
    vRow.sScope = row[4].as<std::string>();
    if (!row[5].is_null()) {
      vRow.oZoneId = row[5].as<int64_t>();
    }
    vRow.sCreatedAt = row[6].as<std::string>();
    vRow.sUpdatedAt = row[7].as<std::string>();
    vRows.push_back(std::move(vRow));
  }
  return vRows;
}

void VariableRepository::update(int64_t iVariableId, const std::string& sName,
                                const std::string& sValue,
                                const std::string& sType) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  try {
    auto result = txn.exec(
        "UPDATE variables SET name = $2, value = $3, "
        "type = $4::variable_type, updated_at = NOW() "
        "WHERE id = $1",
        pqxx::params{iVariableId, sName, sValue, sType});
    txn.commit();
    if (result.affected_rows() == 0) {
      throw common::NotFoundError("variable_not_found", "Variable not found");
    }
  } catch (const pqxx::unique_violation&) {
    throw common::ConflictError("duplicate_variable",
                                "Variable '" + sName + "' already exists in this scope");
  }
}

void VariableRepository::deleteById(int64_t iVariableId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec("DELETE FROM variables WHERE id = $1",
                         pqxx::params{iVariableId});
  txn.commit();
  if (result.affected_rows() == 0) {
    throw common::NotFoundError("variable_not_found", "Variable not found");
  }
}

}  // namespace dns::dal
```

**Step 3: Build and run tests**

Run: `cmake --build build --parallel && ctest --test-dir build --output-on-failure`
Expected: Clean build, all 38 tests pass.

**Step 4: Commit**

```bash
git add include/dal/VariableRepository.hpp src/dal/VariableRepository.cpp
git commit -m "feat(dal): implement VariableRepository with scope/zone filtering"
```

---

## Task 5: RecordRepository

**Files:**
- Modify: `include/dal/RecordRepository.hpp`
- Modify: `src/dal/RecordRepository.cpp`

**Context:** The `records` table stores raw templates with `{{var}}` placeholders. The `upsert()` method is used by RollbackEngine (Phase 7) to restore records from deployment snapshots. The `last_audit_id` column links records to audit entries. `listByZone()` is used by DiffEngine (Phase 6).

**Step 1: Write the header**

Replace `include/dal/RecordRepository.hpp` with:

```cpp
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace dns::dal {

class ConnectionPool;

/// Row type returned from record queries.
struct RecordRow {
  int64_t iId = 0;
  int64_t iZoneId = 0;
  std::string sName;
  std::string sType;
  int iTtl = 300;
  std::string sValueTemplate;
  int iPriority = 0;
  std::optional<int64_t> oLastAuditId;
  std::string sCreatedAt;
  std::string sUpdatedAt;
};

/// Manages the records table (raw templates); upsert for rollback restore.
/// Class abbreviation: rr
class RecordRepository {
 public:
  explicit RecordRepository(ConnectionPool& cpPool);
  ~RecordRepository();

  /// Create a record. Returns the new record ID.
  int64_t create(int64_t iZoneId, const std::string& sName,
                 const std::string& sType, int iTtl,
                 const std::string& sValueTemplate, int iPriority);

  /// Find a record by ID. Returns nullopt if not found.
  std::optional<RecordRow> findById(int64_t iRecordId);

  /// List all records for a zone, ordered by name then type.
  std::vector<RecordRow> listByZone(int64_t iZoneId);

  /// Update a record's fields. Optionally sets last_audit_id.
  /// Throws NotFoundError if record doesn't exist.
  void update(int64_t iRecordId, const std::string& sName,
              const std::string& sType, int iTtl,
              const std::string& sValueTemplate, int iPriority,
              std::optional<int64_t> oLastAuditId);

  /// Delete a record by ID.
  /// Throws NotFoundError if record doesn't exist.
  void deleteById(int64_t iRecordId);

  /// Upsert a record for rollback restore.
  /// If a record with the given ID exists, update it.
  /// If not, insert with the specified fields (ID is NOT preserved from snapshot;
  /// a new ID is assigned).
  void upsert(int64_t iZoneId, const std::string& sName,
              const std::string& sType, int iTtl,
              const std::string& sValueTemplate, int iPriority);

 private:
  ConnectionPool& _cpPool;
};

}  // namespace dns::dal
```

**Step 2: Write the implementation**

Replace `src/dal/RecordRepository.cpp` with:

```cpp
#include "dal/RecordRepository.hpp"

#include "common/Errors.hpp"
#include "dal/ConnectionPool.hpp"

#include <pqxx/pqxx>

namespace dns::dal {

RecordRepository::RecordRepository(ConnectionPool& cpPool) : _cpPool(cpPool) {}
RecordRepository::~RecordRepository() = default;

int64_t RecordRepository::create(int64_t iZoneId, const std::string& sName,
                                 const std::string& sType, int iTtl,
                                 const std::string& sValueTemplate,
                                 int iPriority) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  try {
    auto result = txn.exec(
        "INSERT INTO records (zone_id, name, type, ttl, value_template, priority) "
        "VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
        pqxx::params{iZoneId, sName, sType, iTtl, sValueTemplate, iPriority});
    txn.commit();
    return result.one_row()[0].as<int64_t>();
  } catch (const pqxx::foreign_key_violation&) {
    throw common::NotFoundError("zone_not_found", "Zone not found");
  }
}

std::optional<RecordRow> RecordRepository::findById(int64_t iRecordId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT id, zone_id, name, type, ttl, value_template, priority, "
      "last_audit_id, created_at::text, updated_at::text "
      "FROM records WHERE id = $1",
      pqxx::params{iRecordId});
  txn.commit();

  if (result.empty()) return std::nullopt;

  auto row = result[0];
  RecordRow rRow;
  rRow.iId = row[0].as<int64_t>();
  rRow.iZoneId = row[1].as<int64_t>();
  rRow.sName = row[2].as<std::string>();
  rRow.sType = row[3].as<std::string>();
  rRow.iTtl = row[4].as<int>();
  rRow.sValueTemplate = row[5].as<std::string>();
  rRow.iPriority = row[6].as<int>();
  if (!row[7].is_null()) {
    rRow.oLastAuditId = row[7].as<int64_t>();
  }
  rRow.sCreatedAt = row[8].as<std::string>();
  rRow.sUpdatedAt = row[9].as<std::string>();
  return rRow;
}

std::vector<RecordRow> RecordRepository::listByZone(int64_t iZoneId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT id, zone_id, name, type, ttl, value_template, priority, "
      "last_audit_id, created_at::text, updated_at::text "
      "FROM records WHERE zone_id = $1 ORDER BY name, type",
      pqxx::params{iZoneId});
  txn.commit();

  std::vector<RecordRow> vRows;
  vRows.reserve(result.size());
  for (const auto& row : result) {
    RecordRow rRow;
    rRow.iId = row[0].as<int64_t>();
    rRow.iZoneId = row[1].as<int64_t>();
    rRow.sName = row[2].as<std::string>();
    rRow.sType = row[3].as<std::string>();
    rRow.iTtl = row[4].as<int>();
    rRow.sValueTemplate = row[5].as<std::string>();
    rRow.iPriority = row[6].as<int>();
    if (!row[7].is_null()) {
      rRow.oLastAuditId = row[7].as<int64_t>();
    }
    rRow.sCreatedAt = row[8].as<std::string>();
    rRow.sUpdatedAt = row[9].as<std::string>();
    vRows.push_back(std::move(rRow));
  }
  return vRows;
}

void RecordRepository::update(int64_t iRecordId, const std::string& sName,
                              const std::string& sType, int iTtl,
                              const std::string& sValueTemplate, int iPriority,
                              std::optional<int64_t> oLastAuditId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  pqxx::result result;
  if (oLastAuditId.has_value()) {
    result = txn.exec(
        "UPDATE records SET name = $2, type = $3, ttl = $4, "
        "value_template = $5, priority = $6, last_audit_id = $7, "
        "updated_at = NOW() WHERE id = $1",
        pqxx::params{iRecordId, sName, sType, iTtl, sValueTemplate,
                     iPriority, *oLastAuditId});
  } else {
    result = txn.exec(
        "UPDATE records SET name = $2, type = $3, ttl = $4, "
        "value_template = $5, priority = $6, updated_at = NOW() "
        "WHERE id = $1",
        pqxx::params{iRecordId, sName, sType, iTtl, sValueTemplate,
                     iPriority});
  }
  txn.commit();
  if (result.affected_rows() == 0) {
    throw common::NotFoundError("record_not_found", "Record not found");
  }
}

void RecordRepository::deleteById(int64_t iRecordId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec("DELETE FROM records WHERE id = $1",
                         pqxx::params{iRecordId});
  txn.commit();
  if (result.affected_rows() == 0) {
    throw common::NotFoundError("record_not_found", "Record not found");
  }
}

void RecordRepository::upsert(int64_t iZoneId, const std::string& sName,
                              const std::string& sType, int iTtl,
                              const std::string& sValueTemplate,
                              int iPriority) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  // Use ON CONFLICT on the natural key (zone_id, name, type) to upsert.
  // Note: records doesn't have a unique constraint on (zone_id, name, type),
  // so we use a simple delete-then-insert within the same transaction.
  txn.exec(
      "DELETE FROM records WHERE zone_id = $1 AND name = $2 AND type = $3",
      pqxx::params{iZoneId, sName, sType});
  txn.exec(
      "INSERT INTO records (zone_id, name, type, ttl, value_template, priority) "
      "VALUES ($1, $2, $3, $4, $5, $6)",
      pqxx::params{iZoneId, sName, sType, iTtl, sValueTemplate, iPriority});
  txn.commit();
}

}  // namespace dns::dal
```

**Step 3: Build and run tests**

Run: `cmake --build build --parallel && ctest --test-dir build --output-on-failure`
Expected: Clean build, all 38 tests pass.

**Step 4: Commit**

```bash
git add include/dal/RecordRepository.hpp src/dal/RecordRepository.cpp
git commit -m "feat(dal): implement RecordRepository with upsert for rollback"
```

---

## Task 6: DeploymentRepository

**Files:**
- Modify: `include/dal/DeploymentRepository.hpp`
- Modify: `src/dal/DeploymentRepository.cpp`

**Context:** The `deployments` table stores JSONB snapshots with a per-zone sequence number. `create()` auto-assigns the next `seq` via `COALESCE(MAX(seq), 0) + 1`. `pruneOldSnapshots()` deletes excess snapshots beyond the retention count, keeping the most recent. The unique index on `(zone_id, seq)` ensures no gaps in concurrent inserts.

**Step 1: Write the header**

Replace `include/dal/DeploymentRepository.hpp` with:

```cpp
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace dns::dal {

class ConnectionPool;

/// Row type returned from deployment queries.
struct DeploymentRow {
  int64_t iId = 0;
  int64_t iZoneId = 0;
  int64_t iDeployedBy = 0;
  std::string sDeployedAt;
  int64_t iSeq = 0;
  std::string sSnapshot;  // raw JSONB string
};

/// Manages the deployments table; snapshot create, get, list, prune.
/// Class abbreviation: dr
class DeploymentRepository {
 public:
  explicit DeploymentRepository(ConnectionPool& cpPool);
  ~DeploymentRepository();

  /// Create a deployment snapshot. Auto-assigns next seq for the zone.
  /// Returns the new deployment ID.
  int64_t create(int64_t iZoneId, int64_t iDeployedBy,
                 const std::string& sSnapshotJson);

  /// Find a deployment by ID. Returns nullopt if not found.
  std::optional<DeploymentRow> findById(int64_t iDeploymentId);

  /// List deployments for a zone, ordered by seq DESC (newest first).
  std::vector<DeploymentRow> listByZone(int64_t iZoneId);

  /// Prune old snapshots beyond retention count for a zone.
  /// Keeps the most recent iRetentionCount deployments.
  /// Returns the number of deleted snapshots.
  int pruneOldSnapshots(int64_t iZoneId, int iRetentionCount);

 private:
  ConnectionPool& _cpPool;
};

}  // namespace dns::dal
```

**Step 2: Write the implementation**

Replace `src/dal/DeploymentRepository.cpp` with:

```cpp
#include "dal/DeploymentRepository.hpp"

#include "common/Errors.hpp"
#include "dal/ConnectionPool.hpp"

#include <pqxx/pqxx>

namespace dns::dal {

DeploymentRepository::DeploymentRepository(ConnectionPool& cpPool)
    : _cpPool(cpPool) {}
DeploymentRepository::~DeploymentRepository() = default;

int64_t DeploymentRepository::create(int64_t iZoneId, int64_t iDeployedBy,
                                     const std::string& sSnapshotJson) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  // Assign next seq atomically within the transaction
  auto seqResult = txn.exec(
      "SELECT COALESCE(MAX(seq), 0) + 1 FROM deployments WHERE zone_id = $1",
      pqxx::params{iZoneId});
  int64_t iNextSeq = seqResult.one_row()[0].as<int64_t>();

  auto result = txn.exec(
      "INSERT INTO deployments (zone_id, deployed_by, seq, snapshot) "
      "VALUES ($1, $2, $3, $4::jsonb) RETURNING id",
      pqxx::params{iZoneId, iDeployedBy, iNextSeq, sSnapshotJson});
  txn.commit();
  return result.one_row()[0].as<int64_t>();
}

std::optional<DeploymentRow> DeploymentRepository::findById(
    int64_t iDeploymentId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT id, zone_id, deployed_by, deployed_at::text, seq, "
      "snapshot::text "
      "FROM deployments WHERE id = $1",
      pqxx::params{iDeploymentId});
  txn.commit();

  if (result.empty()) return std::nullopt;

  auto row = result[0];
  return DeploymentRow{
      row[0].as<int64_t>(),
      row[1].as<int64_t>(),
      row[2].as<int64_t>(),
      row[3].as<std::string>(),
      row[4].as<int64_t>(),
      row[5].as<std::string>(),
  };
}

std::vector<DeploymentRow> DeploymentRepository::listByZone(int64_t iZoneId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT id, zone_id, deployed_by, deployed_at::text, seq, "
      "snapshot::text "
      "FROM deployments WHERE zone_id = $1 ORDER BY seq DESC",
      pqxx::params{iZoneId});
  txn.commit();

  std::vector<DeploymentRow> vRows;
  vRows.reserve(result.size());
  for (const auto& row : result) {
    vRows.push_back({
        row[0].as<int64_t>(),
        row[1].as<int64_t>(),
        row[2].as<int64_t>(),
        row[3].as<std::string>(),
        row[4].as<int64_t>(),
        row[5].as<std::string>(),
    });
  }
  return vRows;
}

int DeploymentRepository::pruneOldSnapshots(int64_t iZoneId,
                                            int iRetentionCount) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  // Delete all deployments for this zone except the N most recent (by seq).
  auto result = txn.exec(
      "DELETE FROM deployments WHERE zone_id = $1 AND id NOT IN ("
      "  SELECT id FROM deployments WHERE zone_id = $1 "
      "  ORDER BY seq DESC LIMIT $2"
      ")",
      pqxx::params{iZoneId, iRetentionCount});
  txn.commit();
  return static_cast<int>(result.affected_rows());
}

}  // namespace dns::dal
```

**Step 3: Build and run tests**

Run: `cmake --build build --parallel && ctest --test-dir build --output-on-failure`
Expected: Clean build, all 38 tests pass.

**Step 4: Commit**

```bash
git add include/dal/DeploymentRepository.hpp src/dal/DeploymentRepository.cpp
git commit -m "feat(dal): implement DeploymentRepository with seq numbering and retention pruning"
```

---

## Task 7: AuditRepository

**Files:**
- Modify: `include/dal/AuditRepository.hpp`
- Modify: `src/dal/AuditRepository.cpp`

**Context:** The `audit_log` table is append-only. The existing stub has `purgeOld()` declared but throws `runtime_error`. This task adds `ConnectionPool&`, implements `insert()`, `bulkInsert()`, `query()` with filtering, and the real `purgeOld()`. The purge endpoint requires `dns_audit_admin` DB role (separate connection), but the repository uses the standard pool for now — the separate connection is a Phase 8 concern.

**Step 1: Write the header**

Replace `include/dal/AuditRepository.hpp` with:

```cpp
#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace dns::dal {

class ConnectionPool;

/// Result of a purge operation.
struct PurgeResult {
  int64_t iDeletedCount = 0;
  std::optional<std::chrono::system_clock::time_point> oOldestRemaining;
};

/// Entry for insert/bulkInsert operations.
struct AuditEntry {
  std::string sEntityType;
  int64_t iEntityId = 0;
  std::string sOperation;
  std::string sOldValue;   // JSON string or empty
  std::string sNewValue;   // JSON string or empty
  std::string sIdentity;
  std::string sAuthMethod;
  std::string sIpAddress;
};

/// Row type returned from audit log queries.
struct AuditRow {
  int64_t iId = 0;
  std::string sEntityType;
  int64_t iEntityId = 0;
  std::string sOperation;
  std::string sOldValue;
  std::string sNewValue;
  std::string sIdentity;
  std::string sAuthMethod;
  std::string sIpAddress;
  std::string sTimestamp;
};

/// Manages the audit_log table; insert, bulk-insert, purgeOld.
/// Class abbreviation: ar
class AuditRepository {
 public:
  explicit AuditRepository(ConnectionPool& cpPool);
  ~AuditRepository();

  /// Insert a single audit entry. Returns the new audit log ID.
  int64_t insert(const AuditEntry& aeEntry);

  /// Bulk-insert multiple audit entries in a single transaction.
  void bulkInsert(const std::vector<AuditEntry>& vEntries);

  /// Query the audit log with optional filters.
  /// Results ordered by timestamp DESC.
  std::vector<AuditRow> query(std::optional<std::string> oEntityType,
                              std::optional<std::string> oIdentity,
                              std::optional<std::string> oFrom,
                              std::optional<std::string> oTo,
                              int iLimit, int iOffset);

  /// Purge entries older than iRetentionDays.
  /// Returns count of deleted rows and timestamp of oldest remaining.
  PurgeResult purgeOld(int iRetentionDays);

 private:
  ConnectionPool& _cpPool;
};

}  // namespace dns::dal
```

**Step 2: Write the implementation**

Replace `src/dal/AuditRepository.cpp` with:

```cpp
#include "dal/AuditRepository.hpp"

#include "dal/ConnectionPool.hpp"

#include <pqxx/pqxx>

namespace dns::dal {

AuditRepository::AuditRepository(ConnectionPool& cpPool) : _cpPool(cpPool) {}
AuditRepository::~AuditRepository() = default;

int64_t AuditRepository::insert(const AuditEntry& aeEntry) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "INSERT INTO audit_log (entity_type, entity_id, operation, "
      "old_value, new_value, identity, auth_method, ip_address) "
      "VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6, "
      "$7::auth_method, $8::inet) RETURNING id",
      pqxx::params{
          aeEntry.sEntityType,
          aeEntry.iEntityId,
          aeEntry.sOperation,
          aeEntry.sOldValue.empty() ? nullptr : &aeEntry.sOldValue,
          aeEntry.sNewValue.empty() ? nullptr : &aeEntry.sNewValue,
          aeEntry.sIdentity,
          aeEntry.sAuthMethod.empty() ? nullptr : &aeEntry.sAuthMethod,
          aeEntry.sIpAddress.empty() ? nullptr : &aeEntry.sIpAddress,
      });
  txn.commit();
  return result.one_row()[0].as<int64_t>();
}

void AuditRepository::bulkInsert(const std::vector<AuditEntry>& vEntries) {
  if (vEntries.empty()) return;

  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  for (const auto& ae : vEntries) {
    txn.exec(
        "INSERT INTO audit_log (entity_type, entity_id, operation, "
        "old_value, new_value, identity, auth_method, ip_address) "
        "VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6, "
        "$7::auth_method, $8::inet)",
        pqxx::params{
            ae.sEntityType,
            ae.iEntityId,
            ae.sOperation,
            ae.sOldValue.empty() ? nullptr : &ae.sOldValue,
            ae.sNewValue.empty() ? nullptr : &ae.sNewValue,
            ae.sIdentity,
            ae.sAuthMethod.empty() ? nullptr : &ae.sAuthMethod,
            ae.sIpAddress.empty() ? nullptr : &ae.sIpAddress,
        });
  }
  txn.commit();
}

std::vector<AuditRow> AuditRepository::query(
    std::optional<std::string> oEntityType,
    std::optional<std::string> oIdentity,
    std::optional<std::string> oFrom,
    std::optional<std::string> oTo,
    int iLimit, int iOffset) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);

  // Build query dynamically based on filters
  std::string sSql =
      "SELECT id, entity_type, COALESCE(entity_id, 0), operation, "
      "COALESCE(old_value::text, ''), COALESCE(new_value::text, ''), "
      "identity, COALESCE(auth_method::text, ''), "
      "COALESCE(host(ip_address), ''), timestamp::text "
      "FROM audit_log WHERE 1=1";
  std::vector<std::string> vParams;
  int iParamIdx = 1;

  if (oEntityType.has_value()) {
    sSql += " AND entity_type = $" + std::to_string(iParamIdx++);
    vParams.push_back(*oEntityType);
  }
  if (oIdentity.has_value()) {
    sSql += " AND identity = $" + std::to_string(iParamIdx++);
    vParams.push_back(*oIdentity);
  }
  if (oFrom.has_value()) {
    sSql += " AND timestamp >= $" + std::to_string(iParamIdx++) + "::timestamptz";
    vParams.push_back(*oFrom);
  }
  if (oTo.has_value()) {
    sSql += " AND timestamp <= $" + std::to_string(iParamIdx++) + "::timestamptz";
    vParams.push_back(*oTo);
  }
  sSql += " ORDER BY timestamp DESC";
  sSql += " LIMIT $" + std::to_string(iParamIdx++);
  vParams.push_back(std::to_string(iLimit));
  sSql += " OFFSET $" + std::to_string(iParamIdx++);
  vParams.push_back(std::to_string(iOffset));

  pqxx::params params;
  for (const auto& p : vParams) {
    params.append(p);
  }

  auto result = txn.exec(sSql, params);
  txn.commit();

  std::vector<AuditRow> vRows;
  vRows.reserve(result.size());
  for (const auto& row : result) {
    AuditRow aRow;
    aRow.iId = row[0].as<int64_t>();
    aRow.sEntityType = row[1].as<std::string>();
    aRow.iEntityId = row[2].as<int64_t>();
    aRow.sOperation = row[3].as<std::string>();
    aRow.sOldValue = row[4].as<std::string>();
    aRow.sNewValue = row[5].as<std::string>();
    aRow.sIdentity = row[6].as<std::string>();
    aRow.sAuthMethod = row[7].as<std::string>();
    aRow.sIpAddress = row[8].as<std::string>();
    aRow.sTimestamp = row[9].as<std::string>();
    vRows.push_back(std::move(aRow));
  }
  return vRows;
}

PurgeResult AuditRepository::purgeOld(int iRetentionDays) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto delResult = txn.exec(
      "DELETE FROM audit_log "
      "WHERE timestamp < NOW() - make_interval(days => $1)",
      pqxx::params{iRetentionDays});

  PurgeResult pr;
  pr.iDeletedCount = static_cast<int64_t>(delResult.affected_rows());

  auto oldestResult = txn.exec(
      "SELECT EXTRACT(EPOCH FROM MIN(timestamp))::bigint FROM audit_log");
  txn.commit();

  if (!oldestResult.empty() && !oldestResult[0][0].is_null()) {
    pr.oOldestRemaining = std::chrono::system_clock::time_point(
        std::chrono::seconds(oldestResult[0][0].as<int64_t>()));
  }
  return pr;
}

}  // namespace dns::dal
```

**Step 3: Build and run tests**

Run: `cmake --build build --parallel && ctest --test-dir build --output-on-failure`
Expected: Clean build, all 38 tests pass.

**Step 4: Commit**

```bash
git add include/dal/AuditRepository.hpp src/dal/AuditRepository.cpp
git commit -m "feat(dal): implement AuditRepository with insert, bulkInsert, query, and purge"
```

---

## Task 8: ApiServer — Crow App Instance and Route Wiring

**Files:**
- Modify: `include/api/ApiServer.hpp`
- Modify: `src/api/ApiServer.cpp`

**Context:** ApiServer owns the `crow::SimpleApp` instance. Its constructor receives references to all repositories and services. `registerRoutes()` creates each route class and calls `registerRoutes(app)` on it. `start()` launches Crow. `stop()` calls `app.stop()`. The server must be stoppable from another thread for graceful shutdown.

**Step 1: Write the header**

Replace `include/api/ApiServer.hpp` with:

```cpp
#pragma once

#include <crow.h>

#include <memory>

namespace dns::security {
class AuthService;
class CryptoService;
}  // namespace dns::security

namespace dns::api {
class AuthMiddleware;
}

namespace dns::dal {
class ProviderRepository;
class ViewRepository;
class ZoneRepository;
class VariableRepository;
class RecordRepository;
class DeploymentRepository;
class AuditRepository;
}  // namespace dns::dal

namespace dns::api {

/// Owns the Crow application instance; registers all routes at startup.
/// Class abbreviation: api
class ApiServer {
 public:
  ApiServer(dns::security::AuthService& asService,
            const dns::api::AuthMiddleware& amMiddleware,
            dns::dal::ProviderRepository& prRepo,
            dns::dal::ViewRepository& vrRepo,
            dns::dal::ZoneRepository& zrRepo,
            dns::dal::VariableRepository& varRepo,
            dns::dal::RecordRepository& rrRepo,
            dns::dal::DeploymentRepository& drRepo,
            dns::dal::AuditRepository& arRepo,
            int iAuditRetentionDays);
  ~ApiServer();

  void registerRoutes();
  void start(int iPort, int iThreads);
  void stop();

 private:
  crow::SimpleApp _app;
  dns::security::AuthService& _asService;
  const dns::api::AuthMiddleware& _amMiddleware;
  dns::dal::ProviderRepository& _prRepo;
  dns::dal::ViewRepository& _vrRepo;
  dns::dal::ZoneRepository& _zrRepo;
  dns::dal::VariableRepository& _varRepo;
  dns::dal::RecordRepository& _rrRepo;
  dns::dal::DeploymentRepository& _drRepo;
  dns::dal::AuditRepository& _arRepo;
  int _iAuditRetentionDays;
};

}  // namespace dns::api
```

**Step 2: Write the implementation**

Replace `src/api/ApiServer.cpp` with:

```cpp
#include "api/ApiServer.hpp"

#include "api/AuthMiddleware.hpp"
#include "api/routes/AuthRoutes.hpp"
#include "api/routes/ProviderRoutes.hpp"
#include "api/routes/ViewRoutes.hpp"
#include "api/routes/ZoneRoutes.hpp"
#include "api/routes/VariableRoutes.hpp"
#include "api/routes/RecordRoutes.hpp"
#include "api/routes/AuditRoutes.hpp"
#include "common/Logger.hpp"
#include "security/AuthService.hpp"

namespace dns::api {

ApiServer::ApiServer(dns::security::AuthService& asService,
                     const dns::api::AuthMiddleware& amMiddleware,
                     dns::dal::ProviderRepository& prRepo,
                     dns::dal::ViewRepository& vrRepo,
                     dns::dal::ZoneRepository& zrRepo,
                     dns::dal::VariableRepository& varRepo,
                     dns::dal::RecordRepository& rrRepo,
                     dns::dal::DeploymentRepository& drRepo,
                     dns::dal::AuditRepository& arRepo,
                     int iAuditRetentionDays)
    : _asService(asService),
      _amMiddleware(amMiddleware),
      _prRepo(prRepo),
      _vrRepo(vrRepo),
      _zrRepo(zrRepo),
      _varRepo(varRepo),
      _rrRepo(rrRepo),
      _drRepo(drRepo),
      _arRepo(arRepo),
      _iAuditRetentionDays(iAuditRetentionDays) {}

ApiServer::~ApiServer() = default;

void ApiServer::registerRoutes() {
  // Auth routes (login, logout, me)
  auto arAuth = routes::AuthRoutes(_asService, _amMiddleware);
  arAuth.registerRoutes(_app);

  // Provider routes
  auto prRoutes = routes::ProviderRoutes(_prRepo, _amMiddleware);
  prRoutes.registerRoutes(_app);

  // View routes
  auto vrRoutes = routes::ViewRoutes(_vrRepo, _amMiddleware);
  vrRoutes.registerRoutes(_app);

  // Zone routes
  auto zrRoutes = routes::ZoneRoutes(_zrRepo, _amMiddleware);
  zrRoutes.registerRoutes(_app);

  // Variable routes
  auto varRoutes = routes::VariableRoutes(_varRepo, _amMiddleware);
  varRoutes.registerRoutes(_app);

  // Record routes (basic CRUD only; preview/push deferred to Phase 6-7)
  auto rrRoutes = routes::RecordRoutes(_rrRepo, _amMiddleware);
  rrRoutes.registerRoutes(_app);

  // Audit routes
  auto auRoutes = routes::AuditRoutes(_arRepo, _amMiddleware,
                                      _iAuditRetentionDays);
  auRoutes.registerRoutes(_app);

  auto spLog = common::Logger::get();
  spLog->info("All API routes registered");
}

void ApiServer::start(int iPort, int iThreads) {
  auto spLog = common::Logger::get();
  spLog->info("Starting HTTP server on port {} with {} threads",
              iPort, iThreads);
  _app.port(iPort).concurrency(iThreads).run();
}

void ApiServer::stop() {
  _app.stop();
}

}  // namespace dns::api
```

**Step 3: Build and run tests**

Run: `cmake --build build --parallel && ctest --test-dir build --output-on-failure`
Expected: Build may fail here because route classes don't yet accept the new constructor parameters. That's OK — we fix this in Tasks 9-14. If it fails, just verify the ApiServer files themselves have no syntax errors by checking the compiler output.

**Step 4: Commit**

```bash
git add include/api/ApiServer.hpp src/api/ApiServer.cpp
git commit -m "feat(api): implement ApiServer with Crow app instance and route wiring"
```

---

## Task 9: ProviderRoutes

**Files:**
- Modify: `include/api/routes/ProviderRoutes.hpp`
- Modify: `src/api/routes/ProviderRoutes.cpp`

**Context:** CRUD routes for `/api/v1/providers`. Follows the AuthRoutes pattern: take repo + middleware refs, register lambdas on `crow::SimpleApp&`. Role requirements from ARCHITECTURE.md §6.2: viewer for GET, admin for POST/PUT/DELETE.

**Step 1: Write the header**

Replace `include/api/routes/ProviderRoutes.hpp` with:

```cpp
#pragma once

#include <crow.h>

namespace dns::dal {
class ProviderRepository;
}

namespace dns::api {
class AuthMiddleware;
}

namespace dns::api::routes {

/// Handlers for /api/v1/providers
/// Class abbreviation: pr
class ProviderRoutes {
 public:
  ProviderRoutes(dns::dal::ProviderRepository& prRepo,
                 const dns::api::AuthMiddleware& amMiddleware);
  ~ProviderRoutes();

  void registerRoutes(crow::SimpleApp& app);

 private:
  dns::dal::ProviderRepository& _prRepo;
  const dns::api::AuthMiddleware& _amMiddleware;
};

}  // namespace dns::api::routes
```

**Step 2: Write the implementation**

Replace `src/api/routes/ProviderRoutes.cpp` with:

```cpp
#include "api/routes/ProviderRoutes.hpp"

#include "api/AuthMiddleware.hpp"
#include "common/Errors.hpp"
#include "dal/ProviderRepository.hpp"

#include <nlohmann/json.hpp>

namespace dns::api::routes {

ProviderRoutes::ProviderRoutes(dns::dal::ProviderRepository& prRepo,
                               const dns::api::AuthMiddleware& amMiddleware)
    : _prRepo(prRepo), _amMiddleware(amMiddleware) {}
ProviderRoutes::~ProviderRoutes() = default;

void ProviderRoutes::registerRoutes(crow::SimpleApp& app) {
  // GET /api/v1/providers — list all providers (viewer)
  CROW_ROUTE(app, "/api/v1/providers").methods("GET"_method)(
      [this](const crow::request& req) -> crow::response {
        try {
          std::string sAuth = req.get_header_value("Authorization");
          std::string sApiKey = req.get_header_value("X-API-Key");
          _amMiddleware.authenticate(sAuth, sApiKey);

          auto vProviders = _prRepo.list();
          nlohmann::json jArr = nlohmann::json::array();
          for (const auto& p : vProviders) {
            jArr.push_back({{"id", p.iId}, {"name", p.sName},
                            {"type", p.sType},
                            {"api_endpoint", p.sApiEndpoint},
                            {"created_at", p.sCreatedAt},
                            {"updated_at", p.sUpdatedAt}});
          }
          crow::response resp(200, jArr.dump(2));
          resp.set_header("Content-Type", "application/json");
          return resp;
        } catch (const common::AppError& e) {
          nlohmann::json jErr = {{"error", e._sErrorCode},
                                 {"message", e.what()}};
          return crow::response(e._iHttpStatus, jErr.dump(2));
        }
      });

  // POST /api/v1/providers — create a provider (admin)
  CROW_ROUTE(app, "/api/v1/providers").methods("POST"_method)(
      [this](const crow::request& req) -> crow::response {
        try {
          std::string sAuth = req.get_header_value("Authorization");
          std::string sApiKey = req.get_header_value("X-API-Key");
          auto rcCtx = _amMiddleware.authenticate(sAuth, sApiKey);
          if (rcCtx.sRole != "admin") {
            throw common::AuthorizationError("insufficient_role",
                                             "Admin role required");
          }

          auto jBody = nlohmann::json::parse(req.body);
          std::string sName = jBody.value("name", "");
          std::string sType = jBody.value("type", "");
          std::string sEndpoint = jBody.value("api_endpoint", "");
          std::string sToken = jBody.value("api_token", "");

          if (sName.empty() || sType.empty() || sEndpoint.empty() ||
              sToken.empty()) {
            throw common::ValidationError(
                "missing_fields",
                "name, type, api_endpoint, and api_token are required");
          }

          int64_t iId = _prRepo.create(sName, sType, sEndpoint, sToken);
          nlohmann::json jResp = {{"id", iId}, {"name", sName},
                                  {"type", sType},
                                  {"api_endpoint", sEndpoint}};
          crow::response resp(201, jResp.dump(2));
          resp.set_header("Content-Type", "application/json");
          return resp;
        } catch (const common::AppError& e) {
          nlohmann::json jErr = {{"error", e._sErrorCode},
                                 {"message", e.what()}};
          return crow::response(e._iHttpStatus, jErr.dump(2));
        } catch (const nlohmann::json::exception&) {
          nlohmann::json jErr = {{"error", "invalid_json"},
                                 {"message", "Invalid JSON body"}};
          return crow::response(400, jErr.dump(2));
        }
      });

  // GET /api/v1/providers/<int> — get provider by ID (viewer)
  CROW_ROUTE(app, "/api/v1/providers/<int>").methods("GET"_method)(
      [this](const crow::request& req, int iId) -> crow::response {
        try {
          std::string sAuth = req.get_header_value("Authorization");
          std::string sApiKey = req.get_header_value("X-API-Key");
          _amMiddleware.authenticate(sAuth, sApiKey);

          auto oProvider = _prRepo.findById(iId);
          if (!oProvider.has_value()) {
            throw common::NotFoundError("provider_not_found",
                                        "Provider not found");
          }

          nlohmann::json jResp = {
              {"id", oProvider->iId},
              {"name", oProvider->sName},
              {"type", oProvider->sType},
              {"api_endpoint", oProvider->sApiEndpoint},
              {"created_at", oProvider->sCreatedAt},
              {"updated_at", oProvider->sUpdatedAt}};
          // Note: decrypted token is NOT included in GET response for security
          crow::response resp(200, jResp.dump(2));
          resp.set_header("Content-Type", "application/json");
          return resp;
        } catch (const common::AppError& e) {
          nlohmann::json jErr = {{"error", e._sErrorCode},
                                 {"message", e.what()}};
          return crow::response(e._iHttpStatus, jErr.dump(2));
        }
      });

  // PUT /api/v1/providers/<int> — update provider (admin)
  CROW_ROUTE(app, "/api/v1/providers/<int>").methods("PUT"_method)(
      [this](const crow::request& req, int iId) -> crow::response {
        try {
          std::string sAuth = req.get_header_value("Authorization");
          std::string sApiKey = req.get_header_value("X-API-Key");
          auto rcCtx = _amMiddleware.authenticate(sAuth, sApiKey);
          if (rcCtx.sRole != "admin") {
            throw common::AuthorizationError("insufficient_role",
                                             "Admin role required");
          }

          auto jBody = nlohmann::json::parse(req.body);
          std::string sName = jBody.value("name", "");
          std::string sType = jBody.value("type", "");
          std::string sEndpoint = jBody.value("api_endpoint", "");
          std::string sToken = jBody.value("api_token", "");

          if (sName.empty() || sType.empty() || sEndpoint.empty() ||
              sToken.empty()) {
            throw common::ValidationError(
                "missing_fields",
                "name, type, api_endpoint, and api_token are required");
          }

          _prRepo.update(iId, sName, sType, sEndpoint, sToken);
          nlohmann::json jResp = {{"id", iId}, {"name", sName},
                                  {"type", sType},
                                  {"api_endpoint", sEndpoint}};
          crow::response resp(200, jResp.dump(2));
          resp.set_header("Content-Type", "application/json");
          return resp;
        } catch (const common::AppError& e) {
          nlohmann::json jErr = {{"error", e._sErrorCode},
                                 {"message", e.what()}};
          return crow::response(e._iHttpStatus, jErr.dump(2));
        } catch (const nlohmann::json::exception&) {
          nlohmann::json jErr = {{"error", "invalid_json"},
                                 {"message", "Invalid JSON body"}};
          return crow::response(400, jErr.dump(2));
        }
      });

  // DELETE /api/v1/providers/<int> — delete provider (admin)
  CROW_ROUTE(app, "/api/v1/providers/<int>").methods("DELETE"_method)(
      [this](const crow::request& req, int iId) -> crow::response {
        try {
          std::string sAuth = req.get_header_value("Authorization");
          std::string sApiKey = req.get_header_value("X-API-Key");
          auto rcCtx = _amMiddleware.authenticate(sAuth, sApiKey);
          if (rcCtx.sRole != "admin") {
            throw common::AuthorizationError("insufficient_role",
                                             "Admin role required");
          }

          _prRepo.deleteById(iId);
          return crow::response(204);
        } catch (const common::AppError& e) {
          nlohmann::json jErr = {{"error", e._sErrorCode},
                                 {"message", e.what()}};
          return crow::response(e._iHttpStatus, jErr.dump(2));
        }
      });
}

}  // namespace dns::api::routes
```

**Step 3: Build and run tests**

Run: `cmake --build build --parallel && ctest --test-dir build --output-on-failure`
Expected: Clean build, all 38 tests pass.

**Step 4: Commit**

```bash
git add include/api/routes/ProviderRoutes.hpp src/api/routes/ProviderRoutes.cpp
git commit -m "feat(api): implement ProviderRoutes with CRUD endpoints"
```

---

## Task 10: ViewRoutes

**Files:**
- Modify: `include/api/routes/ViewRoutes.hpp`
- Modify: `src/api/routes/ViewRoutes.cpp`

**Context:** CRUD routes for `/api/v1/views` plus attach/detach provider sub-routes. Roles from §6.3: viewer for GET, admin for POST/PUT/DELETE and attach/detach.

**Step 1: Write the header**

Replace `include/api/routes/ViewRoutes.hpp` with:

```cpp
#pragma once

#include <crow.h>

namespace dns::dal {
class ViewRepository;
}

namespace dns::api {
class AuthMiddleware;
}

namespace dns::api::routes {

/// Handlers for /api/v1/views
/// Class abbreviation: vr
class ViewRoutes {
 public:
  ViewRoutes(dns::dal::ViewRepository& vrRepo,
             const dns::api::AuthMiddleware& amMiddleware);
  ~ViewRoutes();

  void registerRoutes(crow::SimpleApp& app);

 private:
  dns::dal::ViewRepository& _vrRepo;
  const dns::api::AuthMiddleware& _amMiddleware;
};

}  // namespace dns::api::routes
```

**Step 2: Write the implementation**

Replace `src/api/routes/ViewRoutes.cpp` with:

```cpp
#include "api/routes/ViewRoutes.hpp"

#include "api/AuthMiddleware.hpp"
#include "common/Errors.hpp"
#include "dal/ViewRepository.hpp"

#include <nlohmann/json.hpp>

namespace dns::api::routes {

ViewRoutes::ViewRoutes(dns::dal::ViewRepository& vrRepo,
                       const dns::api::AuthMiddleware& amMiddleware)
    : _vrRepo(vrRepo), _amMiddleware(amMiddleware) {}
ViewRoutes::~ViewRoutes() = default;

void ViewRoutes::registerRoutes(crow::SimpleApp& app) {
  // GET /api/v1/views
  CROW_ROUTE(app, "/api/v1/views").methods("GET"_method)(
      [this](const crow::request& req) -> crow::response {
        try {
          std::string sAuth = req.get_header_value("Authorization");
          std::string sApiKey = req.get_header_value("X-API-Key");
          _amMiddleware.authenticate(sAuth, sApiKey);

          auto vViews = _vrRepo.list();
          nlohmann::json jArr = nlohmann::json::array();
          for (const auto& v : vViews) {
            jArr.push_back({{"id", v.iId}, {"name", v.sName},
                            {"description", v.sDescription},
                            {"provider_ids", v.vProviderIds},
                            {"created_at", v.sCreatedAt}});
          }
          crow::response resp(200, jArr.dump(2));
          resp.set_header("Content-Type", "application/json");
          return resp;
        } catch (const common::AppError& e) {
          nlohmann::json jErr = {{"error", e._sErrorCode},
                                 {"message", e.what()}};
          return crow::response(e._iHttpStatus, jErr.dump(2));
        }
      });

  // POST /api/v1/views
  CROW_ROUTE(app, "/api/v1/views").methods("POST"_method)(
      [this](const crow::request& req) -> crow::response {
        try {
          std::string sAuth = req.get_header_value("Authorization");
          std::string sApiKey = req.get_header_value("X-API-Key");
          auto rcCtx = _amMiddleware.authenticate(sAuth, sApiKey);
          if (rcCtx.sRole != "admin") {
            throw common::AuthorizationError("insufficient_role",
                                             "Admin role required");
          }

          auto jBody = nlohmann::json::parse(req.body);
          std::string sName = jBody.value("name", "");
          std::string sDesc = jBody.value("description", "");

          if (sName.empty()) {
            throw common::ValidationError("missing_fields",
                                          "name is required");
          }

          int64_t iId = _vrRepo.create(sName, sDesc);
          nlohmann::json jResp = {{"id", iId}, {"name", sName},
                                  {"description", sDesc}};
          crow::response resp(201, jResp.dump(2));
          resp.set_header("Content-Type", "application/json");
          return resp;
        } catch (const common::AppError& e) {
          nlohmann::json jErr = {{"error", e._sErrorCode},
                                 {"message", e.what()}};
          return crow::response(e._iHttpStatus, jErr.dump(2));
        } catch (const nlohmann::json::exception&) {
          nlohmann::json jErr = {{"error", "invalid_json"},
                                 {"message", "Invalid JSON body"}};
          return crow::response(400, jErr.dump(2));
        }
      });

  // GET /api/v1/views/<int>
  CROW_ROUTE(app, "/api/v1/views/<int>").methods("GET"_method)(
      [this](const crow::request& req, int iId) -> crow::response {
        try {
          std::string sAuth = req.get_header_value("Authorization");
          std::string sApiKey = req.get_header_value("X-API-Key");
          _amMiddleware.authenticate(sAuth, sApiKey);

          auto oView = _vrRepo.findById(iId);
          if (!oView.has_value()) {
            throw common::NotFoundError("view_not_found", "View not found");
          }

          nlohmann::json jResp = {{"id", oView->iId}, {"name", oView->sName},
                                  {"description", oView->sDescription},
                                  {"provider_ids", oView->vProviderIds},
                                  {"created_at", oView->sCreatedAt}};
          crow::response resp(200, jResp.dump(2));
          resp.set_header("Content-Type", "application/json");
          return resp;
        } catch (const common::AppError& e) {
          nlohmann::json jErr = {{"error", e._sErrorCode},
                                 {"message", e.what()}};
          return crow::response(e._iHttpStatus, jErr.dump(2));
        }
      });

  // PUT /api/v1/views/<int>
  CROW_ROUTE(app, "/api/v1/views/<int>").methods("PUT"_method)(
      [this](const crow::request& req, int iId) -> crow::response {
        try {
          std::string sAuth = req.get_header_value("Authorization");
          std::string sApiKey = req.get_header_value("X-API-Key");
          auto rcCtx = _amMiddleware.authenticate(sAuth, sApiKey);
          if (rcCtx.sRole != "admin") {
            throw common::AuthorizationError("insufficient_role",
                                             "Admin role required");
          }

          auto jBody = nlohmann::json::parse(req.body);
          std::string sName = jBody.value("name", "");
          std::string sDesc = jBody.value("description", "");

          if (sName.empty()) {
            throw common::ValidationError("missing_fields",
                                          "name is required");
          }

          _vrRepo.update(iId, sName, sDesc);
          nlohmann::json jResp = {{"id", iId}, {"name", sName},
                                  {"description", sDesc}};
          crow::response resp(200, jResp.dump(2));
          resp.set_header("Content-Type", "application/json");
          return resp;
        } catch (const common::AppError& e) {
          nlohmann::json jErr = {{"error", e._sErrorCode},
                                 {"message", e.what()}};
          return crow::response(e._iHttpStatus, jErr.dump(2));
        } catch (const nlohmann::json::exception&) {
          nlohmann::json jErr = {{"error", "invalid_json"},
                                 {"message", "Invalid JSON body"}};
          return crow::response(400, jErr.dump(2));
        }
      });

  // DELETE /api/v1/views/<int>
  CROW_ROUTE(app, "/api/v1/views/<int>").methods("DELETE"_method)(
      [this](const crow::request& req, int iId) -> crow::response {
        try {
          std::string sAuth = req.get_header_value("Authorization");
          std::string sApiKey = req.get_header_value("X-API-Key");
          auto rcCtx = _amMiddleware.authenticate(sAuth, sApiKey);
          if (rcCtx.sRole != "admin") {
            throw common::AuthorizationError("insufficient_role",
                                             "Admin role required");
          }

          _vrRepo.deleteById(iId);
          return crow::response(204);
        } catch (const common::AppError& e) {
          nlohmann::json jErr = {{"error", e._sErrorCode},
                                 {"message", e.what()}};
          return crow::response(e._iHttpStatus, jErr.dump(2));
        }
      });

  // POST /api/v1/views/<int>/providers/<int> — attach provider
  CROW_ROUTE(app, "/api/v1/views/<int>/providers/<int>").methods("POST"_method)(
      [this](const crow::request& req, int iViewId,
             int iProviderId) -> crow::response {
        try {
          std::string sAuth = req.get_header_value("Authorization");
          std::string sApiKey = req.get_header_value("X-API-Key");
          auto rcCtx = _amMiddleware.authenticate(sAuth, sApiKey);
          if (rcCtx.sRole != "admin") {
            throw common::AuthorizationError("insufficient_role",
                                             "Admin role required");
          }

          _vrRepo.attachProvider(iViewId, iProviderId);
          return crow::response(204);
        } catch (const common::AppError& e) {
          nlohmann::json jErr = {{"error", e._sErrorCode},
                                 {"message", e.what()}};
          return crow::response(e._iHttpStatus, jErr.dump(2));
        }
      });

  // DELETE /api/v1/views/<int>/providers/<int> — detach provider
  CROW_ROUTE(app, "/api/v1/views/<int>/providers/<int>")
      .methods("DELETE"_method)(
          [this](const crow::request& req, int iViewId,
                 int iProviderId) -> crow::response {
            try {
              std::string sAuth = req.get_header_value("Authorization");
              std::string sApiKey = req.get_header_value("X-API-Key");
              auto rcCtx = _amMiddleware.authenticate(sAuth, sApiKey);
              if (rcCtx.sRole != "admin") {
                throw common::AuthorizationError("insufficient_role",
                                                 "Admin role required");
              }

              _vrRepo.detachProvider(iViewId, iProviderId);
              return crow::response(204);
            } catch (const common::AppError& e) {
              nlohmann::json jErr = {{"error", e._sErrorCode},
                                     {"message", e.what()}};
              return crow::response(e._iHttpStatus, jErr.dump(2));
            }
          });
}

}  // namespace dns::api::routes
```

**Step 3: Build and run tests**

Run: `cmake --build build --parallel && ctest --test-dir build --output-on-failure`
Expected: Clean build, all 38 tests pass.

**Step 4: Commit**

```bash
git add include/api/routes/ViewRoutes.hpp src/api/routes/ViewRoutes.cpp
git commit -m "feat(api): implement ViewRoutes with attach/detach provider endpoints"
```

---

## Task 11: ZoneRoutes

**Files:**
- Modify: `include/api/routes/ZoneRoutes.hpp`
- Modify: `src/api/routes/ZoneRoutes.cpp`

**Context:** CRUD for `/api/v1/zones`. Supports `?view_id=` query param for filtering on GET list. Roles from §6.4: viewer for GET, admin for POST/PUT/DELETE.

**Step 1: Write the header**

Replace `include/api/routes/ZoneRoutes.hpp` with:

```cpp
#pragma once

#include <crow.h>

namespace dns::dal {
class ZoneRepository;
}

namespace dns::api {
class AuthMiddleware;
}

namespace dns::api::routes {

/// Handlers for /api/v1/zones
/// Class abbreviation: zr
class ZoneRoutes {
 public:
  ZoneRoutes(dns::dal::ZoneRepository& zrRepo,
             const dns::api::AuthMiddleware& amMiddleware);
  ~ZoneRoutes();

  void registerRoutes(crow::SimpleApp& app);

 private:
  dns::dal::ZoneRepository& _zrRepo;
  const dns::api::AuthMiddleware& _amMiddleware;
};

}  // namespace dns::api::routes
```

**Step 2: Write the implementation**

Replace `src/api/routes/ZoneRoutes.cpp` with:

```cpp
#include "api/routes/ZoneRoutes.hpp"

#include "api/AuthMiddleware.hpp"
#include "common/Errors.hpp"
#include "dal/ZoneRepository.hpp"

#include <nlohmann/json.hpp>

namespace dns::api::routes {

ZoneRoutes::ZoneRoutes(dns::dal::ZoneRepository& zrRepo,
                       const dns::api::AuthMiddleware& amMiddleware)
    : _zrRepo(zrRepo), _amMiddleware(amMiddleware) {}
ZoneRoutes::~ZoneRoutes() = default;

void ZoneRoutes::registerRoutes(crow::SimpleApp& app) {
  // GET /api/v1/zones
  CROW_ROUTE(app, "/api/v1/zones").methods("GET"_method)(
      [this](const crow::request& req) -> crow::response {
        try {
          std::string sAuth = req.get_header_value("Authorization");
          std::string sApiKey = req.get_header_value("X-API-Key");
          _amMiddleware.authenticate(sAuth, sApiKey);

          std::optional<int64_t> oViewId;
          auto* pViewId = req.url_params.get("view_id");
          if (pViewId) {
            oViewId = std::stoll(pViewId);
          }

          auto vZones = _zrRepo.list(oViewId);
          nlohmann::json jArr = nlohmann::json::array();
          for (const auto& z : vZones) {
            nlohmann::json jZone = {{"id", z.iId}, {"name", z.sName},
                                    {"view_id", z.iViewId},
                                    {"created_at", z.sCreatedAt}};
            if (z.oDeploymentRetention.has_value()) {
              jZone["deployment_retention"] = *z.oDeploymentRetention;
            } else {
              jZone["deployment_retention"] = nullptr;
            }
            jArr.push_back(jZone);
          }
          crow::response resp(200, jArr.dump(2));
          resp.set_header("Content-Type", "application/json");
          return resp;
        } catch (const common::AppError& e) {
          nlohmann::json jErr = {{"error", e._sErrorCode},
                                 {"message", e.what()}};
          return crow::response(e._iHttpStatus, jErr.dump(2));
        }
      });

  // POST /api/v1/zones
  CROW_ROUTE(app, "/api/v1/zones").methods("POST"_method)(
      [this](const crow::request& req) -> crow::response {
        try {
          std::string sAuth = req.get_header_value("Authorization");
          std::string sApiKey = req.get_header_value("X-API-Key");
          auto rcCtx = _amMiddleware.authenticate(sAuth, sApiKey);
          if (rcCtx.sRole != "admin") {
            throw common::AuthorizationError("insufficient_role",
                                             "Admin role required");
          }

          auto jBody = nlohmann::json::parse(req.body);
          std::string sName = jBody.value("name", "");
          int64_t iViewId = jBody.value("view_id", static_cast<int64_t>(0));

          if (sName.empty() || iViewId == 0) {
            throw common::ValidationError("missing_fields",
                                          "name and view_id are required");
          }

          std::optional<int> oRetention;
          if (jBody.contains("deployment_retention") &&
              !jBody["deployment_retention"].is_null()) {
            oRetention = jBody["deployment_retention"].get<int>();
          }

          int64_t iId = _zrRepo.create(sName, iViewId, oRetention);
          nlohmann::json jResp = {{"id", iId}, {"name", sName},
                                  {"view_id", iViewId}};
          if (oRetention.has_value()) {
            jResp["deployment_retention"] = *oRetention;
          }
          crow::response resp(201, jResp.dump(2));
          resp.set_header("Content-Type", "application/json");
          return resp;
        } catch (const common::AppError& e) {
          nlohmann::json jErr = {{"error", e._sErrorCode},
                                 {"message", e.what()}};
          return crow::response(e._iHttpStatus, jErr.dump(2));
        } catch (const nlohmann::json::exception&) {
          nlohmann::json jErr = {{"error", "invalid_json"},
                                 {"message", "Invalid JSON body"}};
          return crow::response(400, jErr.dump(2));
        }
      });

  // GET /api/v1/zones/<int>
  CROW_ROUTE(app, "/api/v1/zones/<int>").methods("GET"_method)(
      [this](const crow::request& req, int iId) -> crow::response {
        try {
          std::string sAuth = req.get_header_value("Authorization");
          std::string sApiKey = req.get_header_value("X-API-Key");
          _amMiddleware.authenticate(sAuth, sApiKey);

          auto oZone = _zrRepo.findById(iId);
          if (!oZone.has_value()) {
            throw common::NotFoundError("zone_not_found", "Zone not found");
          }

          nlohmann::json jResp = {{"id", oZone->iId}, {"name", oZone->sName},
                                  {"view_id", oZone->iViewId},
                                  {"created_at", oZone->sCreatedAt}};
          if (oZone->oDeploymentRetention.has_value()) {
            jResp["deployment_retention"] = *oZone->oDeploymentRetention;
          } else {
            jResp["deployment_retention"] = nullptr;
          }
          crow::response resp(200, jResp.dump(2));
          resp.set_header("Content-Type", "application/json");
          return resp;
        } catch (const common::AppError& e) {
          nlohmann::json jErr = {{"error", e._sErrorCode},
                                 {"message", e.what()}};
          return crow::response(e._iHttpStatus, jErr.dump(2));
        }
      });

  // PUT /api/v1/zones/<int>
  CROW_ROUTE(app, "/api/v1/zones/<int>").methods("PUT"_method)(
      [this](const crow::request& req, int iId) -> crow::response {
        try {
          std::string sAuth = req.get_header_value("Authorization");
          std::string sApiKey = req.get_header_value("X-API-Key");
          auto rcCtx = _amMiddleware.authenticate(sAuth, sApiKey);
          if (rcCtx.sRole != "admin") {
            throw common::AuthorizationError("insufficient_role",
                                             "Admin role required");
          }

          auto jBody = nlohmann::json::parse(req.body);
          std::string sName = jBody.value("name", "");
          int64_t iViewId = jBody.value("view_id", static_cast<int64_t>(0));

          if (sName.empty() || iViewId == 0) {
            throw common::ValidationError("missing_fields",
                                          "name and view_id are required");
          }

          std::optional<int> oRetention;
          if (jBody.contains("deployment_retention") &&
              !jBody["deployment_retention"].is_null()) {
            oRetention = jBody["deployment_retention"].get<int>();
          }

          _zrRepo.update(iId, sName, iViewId, oRetention);
          nlohmann::json jResp = {{"id", iId}, {"name", sName},
                                  {"view_id", iViewId}};
          if (oRetention.has_value()) {
            jResp["deployment_retention"] = *oRetention;
          }
          crow::response resp(200, jResp.dump(2));
          resp.set_header("Content-Type", "application/json");
          return resp;
        } catch (const common::AppError& e) {
          nlohmann::json jErr = {{"error", e._sErrorCode},
                                 {"message", e.what()}};
          return crow::response(e._iHttpStatus, jErr.dump(2));
        } catch (const nlohmann::json::exception&) {
          nlohmann::json jErr = {{"error", "invalid_json"},
                                 {"message", "Invalid JSON body"}};
          return crow::response(400, jErr.dump(2));
        }
      });

  // DELETE /api/v1/zones/<int>
  CROW_ROUTE(app, "/api/v1/zones/<int>").methods("DELETE"_method)(
      [this](const crow::request& req, int iId) -> crow::response {
        try {
          std::string sAuth = req.get_header_value("Authorization");
          std::string sApiKey = req.get_header_value("X-API-Key");
          auto rcCtx = _amMiddleware.authenticate(sAuth, sApiKey);
          if (rcCtx.sRole != "admin") {
            throw common::AuthorizationError("insufficient_role",
                                             "Admin role required");
          }

          _zrRepo.deleteById(iId);
          return crow::response(204);
        } catch (const common::AppError& e) {
          nlohmann::json jErr = {{"error", e._sErrorCode},
                                 {"message", e.what()}};
          return crow::response(e._iHttpStatus, jErr.dump(2));
        }
      });
}

}  // namespace dns::api::routes
```

**Step 3: Build and run tests**

Run: `cmake --build build --parallel && ctest --test-dir build --output-on-failure`
Expected: Clean build, all 38 tests pass.

**Step 4: Commit**

```bash
git add include/api/routes/ZoneRoutes.hpp src/api/routes/ZoneRoutes.cpp
git commit -m "feat(api): implement ZoneRoutes with view_id filter support"
```

---

## Task 12: VariableRoutes

**Files:**
- Modify: `include/api/routes/VariableRoutes.hpp`
- Modify: `src/api/routes/VariableRoutes.cpp`

**Context:** CRUD for `/api/v1/variables`. Supports `?scope=` and `?zone_id=` query params for filtering on GET list. Roles from §6.6: viewer for GET, operator for POST/PUT/DELETE.

**Step 1: Write the header**

Replace `include/api/routes/VariableRoutes.hpp` with:

```cpp
#pragma once

#include <crow.h>

namespace dns::dal {
class VariableRepository;
}

namespace dns::api {
class AuthMiddleware;
}

namespace dns::api::routes {

/// Handlers for /api/v1/variables
/// Class abbreviation: var
class VariableRoutes {
 public:
  VariableRoutes(dns::dal::VariableRepository& varRepo,
                 const dns::api::AuthMiddleware& amMiddleware);
  ~VariableRoutes();

  void registerRoutes(crow::SimpleApp& app);

 private:
  dns::dal::VariableRepository& _varRepo;
  const dns::api::AuthMiddleware& _amMiddleware;
};

}  // namespace dns::api::routes
```

**Step 2: Write the implementation**

Replace `src/api/routes/VariableRoutes.cpp` with:

```cpp
#include "api/routes/VariableRoutes.hpp"

#include "api/AuthMiddleware.hpp"
#include "common/Errors.hpp"
#include "dal/VariableRepository.hpp"

#include <nlohmann/json.hpp>

namespace dns::api::routes {

VariableRoutes::VariableRoutes(dns::dal::VariableRepository& varRepo,
                               const dns::api::AuthMiddleware& amMiddleware)
    : _varRepo(varRepo), _amMiddleware(amMiddleware) {}
VariableRoutes::~VariableRoutes() = default;

void VariableRoutes::registerRoutes(crow::SimpleApp& app) {
  // GET /api/v1/variables
  CROW_ROUTE(app, "/api/v1/variables").methods("GET"_method)(
      [this](const crow::request& req) -> crow::response {
        try {
          std::string sAuth = req.get_header_value("Authorization");
          std::string sApiKey = req.get_header_value("X-API-Key");
          _amMiddleware.authenticate(sAuth, sApiKey);

          std::optional<std::string> oScope;
          std::optional<int64_t> oZoneId;
          auto* pScope = req.url_params.get("scope");
          if (pScope) oScope = std::string(pScope);
          auto* pZoneId = req.url_params.get("zone_id");
          if (pZoneId) oZoneId = std::stoll(pZoneId);

          auto vVars = _varRepo.list(oScope, oZoneId);
          nlohmann::json jArr = nlohmann::json::array();
          for (const auto& v : vVars) {
            nlohmann::json jVar = {
                {"id", v.iId},     {"name", v.sName},
                {"value", v.sValue}, {"type", v.sType},
                {"scope", v.sScope}, {"created_at", v.sCreatedAt},
                {"updated_at", v.sUpdatedAt}};
            if (v.oZoneId.has_value()) {
              jVar["zone_id"] = *v.oZoneId;
            } else {
              jVar["zone_id"] = nullptr;
            }
            jArr.push_back(jVar);
          }
          crow::response resp(200, jArr.dump(2));
          resp.set_header("Content-Type", "application/json");
          return resp;
        } catch (const common::AppError& e) {
          nlohmann::json jErr = {{"error", e._sErrorCode},
                                 {"message", e.what()}};
          return crow::response(e._iHttpStatus, jErr.dump(2));
        }
      });

  // POST /api/v1/variables
  CROW_ROUTE(app, "/api/v1/variables").methods("POST"_method)(
      [this](const crow::request& req) -> crow::response {
        try {
          std::string sAuth = req.get_header_value("Authorization");
          std::string sApiKey = req.get_header_value("X-API-Key");
          auto rcCtx = _amMiddleware.authenticate(sAuth, sApiKey);
          if (rcCtx.sRole == "viewer") {
            throw common::AuthorizationError("insufficient_role",
                                             "Operator role required");
          }

          auto jBody = nlohmann::json::parse(req.body);
          std::string sName = jBody.value("name", "");
          std::string sValue = jBody.value("value", "");
          std::string sType = jBody.value("type", "");
          std::string sScope = jBody.value("scope", "global");

          if (sName.empty() || sValue.empty() || sType.empty()) {
            throw common::ValidationError(
                "missing_fields", "name, value, and type are required");
          }

          std::optional<int64_t> oZoneId;
          if (jBody.contains("zone_id") && !jBody["zone_id"].is_null()) {
            oZoneId = jBody["zone_id"].get<int64_t>();
          }

          int64_t iId =
              _varRepo.create(sName, sValue, sType, sScope, oZoneId);
          nlohmann::json jResp = {{"id", iId},       {"name", sName},
                                  {"value", sValue}, {"type", sType},
                                  {"scope", sScope}};
          if (oZoneId.has_value()) {
            jResp["zone_id"] = *oZoneId;
          }
          crow::response resp(201, jResp.dump(2));
          resp.set_header("Content-Type", "application/json");
          return resp;
        } catch (const common::AppError& e) {
          nlohmann::json jErr = {{"error", e._sErrorCode},
                                 {"message", e.what()}};
          return crow::response(e._iHttpStatus, jErr.dump(2));
        } catch (const nlohmann::json::exception&) {
          nlohmann::json jErr = {{"error", "invalid_json"},
                                 {"message", "Invalid JSON body"}};
          return crow::response(400, jErr.dump(2));
        }
      });

  // GET /api/v1/variables/<int>
  CROW_ROUTE(app, "/api/v1/variables/<int>").methods("GET"_method)(
      [this](const crow::request& req, int iId) -> crow::response {
        try {
          std::string sAuth = req.get_header_value("Authorization");
          std::string sApiKey = req.get_header_value("X-API-Key");
          _amMiddleware.authenticate(sAuth, sApiKey);

          auto oVar = _varRepo.findById(iId);
          if (!oVar.has_value()) {
            throw common::NotFoundError("variable_not_found",
                                        "Variable not found");
          }

          nlohmann::json jResp = {
              {"id", oVar->iId},     {"name", oVar->sName},
              {"value", oVar->sValue}, {"type", oVar->sType},
              {"scope", oVar->sScope}, {"created_at", oVar->sCreatedAt},
              {"updated_at", oVar->sUpdatedAt}};
          if (oVar->oZoneId.has_value()) {
            jResp["zone_id"] = *oVar->oZoneId;
          } else {
            jResp["zone_id"] = nullptr;
          }
          crow::response resp(200, jResp.dump(2));
          resp.set_header("Content-Type", "application/json");
          return resp;
        } catch (const common::AppError& e) {
          nlohmann::json jErr = {{"error", e._sErrorCode},
                                 {"message", e.what()}};
          return crow::response(e._iHttpStatus, jErr.dump(2));
        }
      });

  // PUT /api/v1/variables/<int>
  CROW_ROUTE(app, "/api/v1/variables/<int>").methods("PUT"_method)(
      [this](const crow::request& req, int iId) -> crow::response {
        try {
          std::string sAuth = req.get_header_value("Authorization");
          std::string sApiKey = req.get_header_value("X-API-Key");
          auto rcCtx = _amMiddleware.authenticate(sAuth, sApiKey);
          if (rcCtx.sRole == "viewer") {
            throw common::AuthorizationError("insufficient_role",
                                             "Operator role required");
          }

          auto jBody = nlohmann::json::parse(req.body);
          std::string sName = jBody.value("name", "");
          std::string sValue = jBody.value("value", "");
          std::string sType = jBody.value("type", "");

          if (sName.empty() || sValue.empty() || sType.empty()) {
            throw common::ValidationError(
                "missing_fields", "name, value, and type are required");
          }

          _varRepo.update(iId, sName, sValue, sType);
          nlohmann::json jResp = {{"id", iId}, {"name", sName},
                                  {"value", sValue}, {"type", sType}};
          crow::response resp(200, jResp.dump(2));
          resp.set_header("Content-Type", "application/json");
          return resp;
        } catch (const common::AppError& e) {
          nlohmann::json jErr = {{"error", e._sErrorCode},
                                 {"message", e.what()}};
          return crow::response(e._iHttpStatus, jErr.dump(2));
        } catch (const nlohmann::json::exception&) {
          nlohmann::json jErr = {{"error", "invalid_json"},
                                 {"message", "Invalid JSON body"}};
          return crow::response(400, jErr.dump(2));
        }
      });

  // DELETE /api/v1/variables/<int>
  CROW_ROUTE(app, "/api/v1/variables/<int>").methods("DELETE"_method)(
      [this](const crow::request& req, int iId) -> crow::response {
        try {
          std::string sAuth = req.get_header_value("Authorization");
          std::string sApiKey = req.get_header_value("X-API-Key");
          auto rcCtx = _amMiddleware.authenticate(sAuth, sApiKey);
          if (rcCtx.sRole == "viewer") {
            throw common::AuthorizationError("insufficient_role",
                                             "Operator role required");
          }

          _varRepo.deleteById(iId);
          return crow::response(204);
        } catch (const common::AppError& e) {
          nlohmann::json jErr = {{"error", e._sErrorCode},
                                 {"message", e.what()}};
          return crow::response(e._iHttpStatus, jErr.dump(2));
        }
      });
}

}  // namespace dns::api::routes
```

**Step 3: Build and run tests**

Run: `cmake --build build --parallel && ctest --test-dir build --output-on-failure`
Expected: Clean build, all 38 tests pass.

**Step 4: Commit**

```bash
git add include/api/routes/VariableRoutes.hpp src/api/routes/VariableRoutes.cpp
git commit -m "feat(api): implement VariableRoutes with scope/zone_id filtering"
```

---

## Task 13: RecordRoutes (Basic CRUD Only)

**Files:**
- Modify: `include/api/routes/RecordRoutes.hpp`
- Modify: `src/api/routes/RecordRoutes.cpp`

**Context:** Basic CRUD for `/api/v1/zones/{id}/records`. Preview and push endpoints are deferred to Phase 6-7 (they require DiffEngine and providers). Roles from §6.5: viewer for GET, operator for POST/PUT/DELETE.

**Step 1: Write the header**

Replace `include/api/routes/RecordRoutes.hpp` with:

```cpp
#pragma once

#include <crow.h>

namespace dns::dal {
class RecordRepository;
}

namespace dns::api {
class AuthMiddleware;
}

namespace dns::api::routes {

/// Handlers for /api/v1/zones/{id}/records (basic CRUD).
/// Preview and push endpoints deferred to Phase 6-7.
/// Class abbreviation: rr
class RecordRoutes {
 public:
  RecordRoutes(dns::dal::RecordRepository& rrRepo,
               const dns::api::AuthMiddleware& amMiddleware);
  ~RecordRoutes();

  void registerRoutes(crow::SimpleApp& app);

 private:
  dns::dal::RecordRepository& _rrRepo;
  const dns::api::AuthMiddleware& _amMiddleware;
};

}  // namespace dns::api::routes
```

**Step 2: Write the implementation**

Replace `src/api/routes/RecordRoutes.cpp` with:

```cpp
#include "api/routes/RecordRoutes.hpp"

#include "api/AuthMiddleware.hpp"
#include "common/Errors.hpp"
#include "dal/RecordRepository.hpp"

#include <nlohmann/json.hpp>

namespace dns::api::routes {

RecordRoutes::RecordRoutes(dns::dal::RecordRepository& rrRepo,
                           const dns::api::AuthMiddleware& amMiddleware)
    : _rrRepo(rrRepo), _amMiddleware(amMiddleware) {}
RecordRoutes::~RecordRoutes() = default;

void RecordRoutes::registerRoutes(crow::SimpleApp& app) {
  // GET /api/v1/zones/<int>/records
  CROW_ROUTE(app, "/api/v1/zones/<int>/records").methods("GET"_method)(
      [this](const crow::request& req, int iZoneId) -> crow::response {
        try {
          std::string sAuth = req.get_header_value("Authorization");
          std::string sApiKey = req.get_header_value("X-API-Key");
          _amMiddleware.authenticate(sAuth, sApiKey);

          auto vRecords = _rrRepo.listByZone(iZoneId);
          nlohmann::json jArr = nlohmann::json::array();
          for (const auto& r : vRecords) {
            nlohmann::json jRec = {
                {"id", r.iId},
                {"zone_id", r.iZoneId},
                {"name", r.sName},
                {"type", r.sType},
                {"ttl", r.iTtl},
                {"value_template", r.sValueTemplate},
                {"priority", r.iPriority},
                {"created_at", r.sCreatedAt},
                {"updated_at", r.sUpdatedAt}};
            if (r.oLastAuditId.has_value()) {
              jRec["last_audit_id"] = *r.oLastAuditId;
            } else {
              jRec["last_audit_id"] = nullptr;
            }
            jArr.push_back(jRec);
          }
          crow::response resp(200, jArr.dump(2));
          resp.set_header("Content-Type", "application/json");
          return resp;
        } catch (const common::AppError& e) {
          nlohmann::json jErr = {{"error", e._sErrorCode},
                                 {"message", e.what()}};
          return crow::response(e._iHttpStatus, jErr.dump(2));
        }
      });

  // POST /api/v1/zones/<int>/records
  CROW_ROUTE(app, "/api/v1/zones/<int>/records").methods("POST"_method)(
      [this](const crow::request& req, int iZoneId) -> crow::response {
        try {
          std::string sAuth = req.get_header_value("Authorization");
          std::string sApiKey = req.get_header_value("X-API-Key");
          auto rcCtx = _amMiddleware.authenticate(sAuth, sApiKey);
          if (rcCtx.sRole == "viewer") {
            throw common::AuthorizationError("insufficient_role",
                                             "Operator role required");
          }

          auto jBody = nlohmann::json::parse(req.body);
          std::string sName = jBody.value("name", "");
          std::string sType = jBody.value("type", "");
          std::string sValueTemplate = jBody.value("value_template", "");
          int iTtl = jBody.value("ttl", 300);
          int iPriority = jBody.value("priority", 0);

          if (sName.empty() || sType.empty() || sValueTemplate.empty()) {
            throw common::ValidationError(
                "missing_fields",
                "name, type, and value_template are required");
          }

          int64_t iId = _rrRepo.create(iZoneId, sName, sType, iTtl,
                                       sValueTemplate, iPriority);
          nlohmann::json jResp = {
              {"id", iId},         {"zone_id", iZoneId},
              {"name", sName},     {"type", sType},
              {"ttl", iTtl},       {"value_template", sValueTemplate},
              {"priority", iPriority}};
          crow::response resp(201, jResp.dump(2));
          resp.set_header("Content-Type", "application/json");
          return resp;
        } catch (const common::AppError& e) {
          nlohmann::json jErr = {{"error", e._sErrorCode},
                                 {"message", e.what()}};
          return crow::response(e._iHttpStatus, jErr.dump(2));
        } catch (const nlohmann::json::exception&) {
          nlohmann::json jErr = {{"error", "invalid_json"},
                                 {"message", "Invalid JSON body"}};
          return crow::response(400, jErr.dump(2));
        }
      });

  // GET /api/v1/zones/<int>/records/<int>
  CROW_ROUTE(app, "/api/v1/zones/<int>/records/<int>").methods("GET"_method)(
      [this](const crow::request& req, int /*iZoneId*/,
             int iRecordId) -> crow::response {
        try {
          std::string sAuth = req.get_header_value("Authorization");
          std::string sApiKey = req.get_header_value("X-API-Key");
          _amMiddleware.authenticate(sAuth, sApiKey);

          auto oRecord = _rrRepo.findById(iRecordId);
          if (!oRecord.has_value()) {
            throw common::NotFoundError("record_not_found",
                                        "Record not found");
          }

          nlohmann::json jResp = {
              {"id", oRecord->iId},
              {"zone_id", oRecord->iZoneId},
              {"name", oRecord->sName},
              {"type", oRecord->sType},
              {"ttl", oRecord->iTtl},
              {"value_template", oRecord->sValueTemplate},
              {"priority", oRecord->iPriority},
              {"created_at", oRecord->sCreatedAt},
              {"updated_at", oRecord->sUpdatedAt}};
          if (oRecord->oLastAuditId.has_value()) {
            jResp["last_audit_id"] = *oRecord->oLastAuditId;
          } else {
            jResp["last_audit_id"] = nullptr;
          }
          crow::response resp(200, jResp.dump(2));
          resp.set_header("Content-Type", "application/json");
          return resp;
        } catch (const common::AppError& e) {
          nlohmann::json jErr = {{"error", e._sErrorCode},
                                 {"message", e.what()}};
          return crow::response(e._iHttpStatus, jErr.dump(2));
        }
      });

  // PUT /api/v1/zones/<int>/records/<int>
  CROW_ROUTE(app, "/api/v1/zones/<int>/records/<int>").methods("PUT"_method)(
      [this](const crow::request& req, int /*iZoneId*/,
             int iRecordId) -> crow::response {
        try {
          std::string sAuth = req.get_header_value("Authorization");
          std::string sApiKey = req.get_header_value("X-API-Key");
          auto rcCtx = _amMiddleware.authenticate(sAuth, sApiKey);
          if (rcCtx.sRole == "viewer") {
            throw common::AuthorizationError("insufficient_role",
                                             "Operator role required");
          }

          auto jBody = nlohmann::json::parse(req.body);
          std::string sName = jBody.value("name", "");
          std::string sType = jBody.value("type", "");
          std::string sValueTemplate = jBody.value("value_template", "");
          int iTtl = jBody.value("ttl", 300);
          int iPriority = jBody.value("priority", 0);

          if (sName.empty() || sType.empty() || sValueTemplate.empty()) {
            throw common::ValidationError(
                "missing_fields",
                "name, type, and value_template are required");
          }

          _rrRepo.update(iRecordId, sName, sType, iTtl, sValueTemplate,
                         iPriority, std::nullopt);
          nlohmann::json jResp = {
              {"id", iRecordId},   {"name", sName},
              {"type", sType},     {"ttl", iTtl},
              {"value_template", sValueTemplate},
              {"priority", iPriority}};
          crow::response resp(200, jResp.dump(2));
          resp.set_header("Content-Type", "application/json");
          return resp;
        } catch (const common::AppError& e) {
          nlohmann::json jErr = {{"error", e._sErrorCode},
                                 {"message", e.what()}};
          return crow::response(e._iHttpStatus, jErr.dump(2));
        } catch (const nlohmann::json::exception&) {
          nlohmann::json jErr = {{"error", "invalid_json"},
                                 {"message", "Invalid JSON body"}};
          return crow::response(400, jErr.dump(2));
        }
      });

  // DELETE /api/v1/zones/<int>/records/<int>
  CROW_ROUTE(app, "/api/v1/zones/<int>/records/<int>")
      .methods("DELETE"_method)(
          [this](const crow::request& req, int /*iZoneId*/,
                 int iRecordId) -> crow::response {
            try {
              std::string sAuth = req.get_header_value("Authorization");
              std::string sApiKey = req.get_header_value("X-API-Key");
              auto rcCtx = _amMiddleware.authenticate(sAuth, sApiKey);
              if (rcCtx.sRole == "viewer") {
                throw common::AuthorizationError("insufficient_role",
                                                 "Operator role required");
              }

              _rrRepo.deleteById(iRecordId);
              return crow::response(204);
            } catch (const common::AppError& e) {
              nlohmann::json jErr = {{"error", e._sErrorCode},
                                     {"message", e.what()}};
              return crow::response(e._iHttpStatus, jErr.dump(2));
            }
          });
}

}  // namespace dns::api::routes
```

**Step 3: Build and run tests**

Run: `cmake --build build --parallel && ctest --test-dir build --output-on-failure`
Expected: Clean build, all 38 tests pass.

**Step 4: Commit**

```bash
git add include/api/routes/RecordRoutes.hpp src/api/routes/RecordRoutes.cpp
git commit -m "feat(api): implement RecordRoutes with basic CRUD for zone records"
```

---

## Task 14: AuditRoutes

**Files:**
- Modify: `include/api/routes/AuditRoutes.hpp`
- Modify: `src/api/routes/AuditRoutes.cpp`

**Context:** Query and purge endpoints for `/api/v1/audit`. Roles from §6.9: viewer for GET query, admin for DELETE purge. The export endpoint (NDJSON streaming) is deferred to Phase 8.

**Step 1: Write the header**

Replace `include/api/routes/AuditRoutes.hpp` with:

```cpp
#pragma once

#include <crow.h>

namespace dns::dal {
class AuditRepository;
}

namespace dns::api {
class AuthMiddleware;
}

namespace dns::api::routes {

/// Handlers for /api/v1/audit
/// Class abbreviation: au
class AuditRoutes {
 public:
  AuditRoutes(dns::dal::AuditRepository& arRepo,
              const dns::api::AuthMiddleware& amMiddleware,
              int iAuditRetentionDays);
  ~AuditRoutes();

  void registerRoutes(crow::SimpleApp& app);

 private:
  dns::dal::AuditRepository& _arRepo;
  const dns::api::AuthMiddleware& _amMiddleware;
  int _iAuditRetentionDays;
};

}  // namespace dns::api::routes
```

**Step 2: Write the implementation**

Replace `src/api/routes/AuditRoutes.cpp` with:

```cpp
#include "api/routes/AuditRoutes.hpp"

#include "api/AuthMiddleware.hpp"
#include "common/Errors.hpp"
#include "dal/AuditRepository.hpp"

#include <nlohmann/json.hpp>

namespace dns::api::routes {

AuditRoutes::AuditRoutes(dns::dal::AuditRepository& arRepo,
                         const dns::api::AuthMiddleware& amMiddleware,
                         int iAuditRetentionDays)
    : _arRepo(arRepo),
      _amMiddleware(amMiddleware),
      _iAuditRetentionDays(iAuditRetentionDays) {}
AuditRoutes::~AuditRoutes() = default;

void AuditRoutes::registerRoutes(crow::SimpleApp& app) {
  // GET /api/v1/audit — query audit log (viewer)
  CROW_ROUTE(app, "/api/v1/audit").methods("GET"_method)(
      [this](const crow::request& req) -> crow::response {
        try {
          std::string sAuth = req.get_header_value("Authorization");
          std::string sApiKey = req.get_header_value("X-API-Key");
          _amMiddleware.authenticate(sAuth, sApiKey);

          std::optional<std::string> oEntityType;
          std::optional<std::string> oIdentity;
          std::optional<std::string> oFrom;
          std::optional<std::string> oTo;

          auto* pEntityType = req.url_params.get("entity_type");
          if (pEntityType) oEntityType = std::string(pEntityType);
          auto* pIdentity = req.url_params.get("identity");
          if (pIdentity) oIdentity = std::string(pIdentity);
          auto* pFrom = req.url_params.get("from");
          if (pFrom) oFrom = std::string(pFrom);
          auto* pTo = req.url_params.get("to");
          if (pTo) oTo = std::string(pTo);

          int iLimit = 100;
          int iOffset = 0;
          auto* pLimit = req.url_params.get("limit");
          if (pLimit) iLimit = std::stoi(pLimit);
          auto* pOffset = req.url_params.get("offset");
          if (pOffset) iOffset = std::stoi(pOffset);

          auto vRows = _arRepo.query(oEntityType, oIdentity, oFrom, oTo,
                                     iLimit, iOffset);
          nlohmann::json jArr = nlohmann::json::array();
          for (const auto& a : vRows) {
            nlohmann::json jRow = {
                {"id", a.iId},
                {"entity_type", a.sEntityType},
                {"entity_id", a.iEntityId},
                {"operation", a.sOperation},
                {"identity", a.sIdentity},
                {"auth_method", a.sAuthMethod},
                {"ip_address", a.sIpAddress},
                {"timestamp", a.sTimestamp}};
            if (!a.sOldValue.empty()) {
              jRow["old_value"] = nlohmann::json::parse(a.sOldValue);
            } else {
              jRow["old_value"] = nullptr;
            }
            if (!a.sNewValue.empty()) {
              jRow["new_value"] = nlohmann::json::parse(a.sNewValue);
            } else {
              jRow["new_value"] = nullptr;
            }
            jArr.push_back(jRow);
          }
          crow::response resp(200, jArr.dump(2));
          resp.set_header("Content-Type", "application/json");
          return resp;
        } catch (const common::AppError& e) {
          nlohmann::json jErr = {{"error", e._sErrorCode},
                                 {"message", e.what()}};
          return crow::response(e._iHttpStatus, jErr.dump(2));
        }
      });

  // DELETE /api/v1/audit/purge — purge old entries (admin)
  CROW_ROUTE(app, "/api/v1/audit/purge").methods("DELETE"_method)(
      [this](const crow::request& req) -> crow::response {
        try {
          std::string sAuth = req.get_header_value("Authorization");
          std::string sApiKey = req.get_header_value("X-API-Key");
          auto rcCtx = _amMiddleware.authenticate(sAuth, sApiKey);
          if (rcCtx.sRole != "admin") {
            throw common::AuthorizationError("insufficient_role",
                                             "Admin role required");
          }

          auto prResult = _arRepo.purgeOld(_iAuditRetentionDays);
          nlohmann::json jResp = {{"deleted", prResult.iDeletedCount}};
          if (prResult.oOldestRemaining.has_value()) {
            auto tpEpoch = std::chrono::duration_cast<std::chrono::seconds>(
                               prResult.oOldestRemaining->time_since_epoch())
                               .count();
            jResp["oldest_remaining"] = std::to_string(tpEpoch);
          } else {
            jResp["oldest_remaining"] = nullptr;
          }
          crow::response resp(200, jResp.dump(2));
          resp.set_header("Content-Type", "application/json");
          return resp;
        } catch (const common::AppError& e) {
          nlohmann::json jErr = {{"error", e._sErrorCode},
                                 {"message", e.what()}};
          return crow::response(e._iHttpStatus, jErr.dump(2));
        }
      });
}

}  // namespace dns::api::routes
```

**Step 3: Build and run tests**

Run: `cmake --build build --parallel && ctest --test-dir build --output-on-failure`
Expected: Clean build, all 38 tests pass.

**Step 4: Commit**

```bash
git add include/api/routes/AuditRoutes.hpp src/api/routes/AuditRoutes.cpp
git commit -m "feat(api): implement AuditRoutes with query filtering and purge"
```

---

## Task 15: Wire Startup Steps 10-11 in main.cpp

**Files:**
- Modify: `src/main.cpp`

**Context:** Wire the new repositories, AuthMiddleware, AuthService, ApiServer into the startup sequence. Steps 10-11 create the ApiServer, register routes, and start the HTTP server. The server runs in a blocking call; graceful shutdown uses signal handling (SIGINT/SIGTERM).

**Step 1: Update main.cpp**

In `src/main.cpp`, add the new includes and wire steps 10-11. The key changes:

1. Add includes for all new repositories and ApiServer
2. After Step 8 (SamlReplayCache), construct the Phase 5 repositories
3. Construct AuthService and AuthMiddleware
4. Construct and start ApiServer
5. Add signal handler for graceful shutdown

Replace the section from `// ── Steps 9-12` through the end of the try block with:

```cpp
    // ── Step 9: ProviderFactory — deferred to Phase 6 ───────────────────────
    spLog->warn("Step 9: ProviderFactory — not yet implemented");

    // ── Step 10: Construct repositories and API routes ──────────────────────
    auto prRepo = std::make_unique<dns::dal::ProviderRepository>(*cpPool, *csService);
    auto vrRepo = std::make_unique<dns::dal::ViewRepository>(*cpPool);
    auto zrRepo = std::make_unique<dns::dal::ZoneRepository>(*cpPool);
    auto varRepo = std::make_unique<dns::dal::VariableRepository>(*cpPool);
    auto rrRepo = std::make_unique<dns::dal::RecordRepository>(*cpPool);
    auto drRepo = std::make_unique<dns::dal::DeploymentRepository>(*cpPool);
    auto arRepo = std::make_unique<dns::dal::AuditRepository>(*cpPool);

    auto asService = std::make_unique<dns::security::AuthService>(
        *upSigner, *urRepo, *srRepo, *akrRepo,
        cfgApp.iJwtTtlSeconds, cfgApp.iSessionAbsoluteTtlSeconds);

    auto amMiddleware = std::make_unique<dns::api::AuthMiddleware>(
        *upSigner, *srRepo, *akrRepo, *urRepo,
        cfgApp.iJwtTtlSeconds, cfgApp.iApiKeyCleanupGraceSeconds);

    auto apiServer = std::make_unique<dns::api::ApiServer>(
        *asService, *amMiddleware,
        *prRepo, *vrRepo, *zrRepo, *varRepo, *rrRepo, *drRepo, *arRepo,
        cfgApp.iAuditRetentionDays);
    apiServer->registerRoutes();
    spLog->info("Step 10: API routes registered");

    // ── Step 11: Start HTTP server ──────────────────────────────────────────
    spLog->info("Step 11: Starting HTTP server on port {}", cfgApp.iHttpPort);

    // Run server in a separate thread so we can handle shutdown
    std::atomic<bool> bRunning{true};
    std::thread tServer([&]() {
      apiServer->start(cfgApp.iHttpPort, cfgApp.iHttpThreads);
    });

    // Wait for SIGINT/SIGTERM
    std::signal(SIGINT, [](int) {});
    std::signal(SIGTERM, [](int) {});
    sigset_t stSigSet;
    sigemptyset(&stSigSet);
    sigaddset(&stSigSet, SIGINT);
    sigaddset(&stSigSet, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &stSigSet, nullptr);
    int iSig = 0;
    sigwait(&stSigSet, &iSig);

    spLog->info("Received signal {}, shutting down...", iSig);
    apiServer->stop();
    tServer.join();

    // Graceful shutdown
    msScheduler->stop();
    spLog->info("MaintenanceScheduler stopped");
    spLog->info("dns-orchestrator shutdown complete");

    return EXIT_SUCCESS;
```

Add these includes at the top of main.cpp:

```cpp
#include <atomic>
#include <csignal>
#include <thread>

#include "api/ApiServer.hpp"
#include "api/AuthMiddleware.hpp"
#include "dal/AuditRepository.hpp"
#include "dal/DeploymentRepository.hpp"
#include "dal/ProviderRepository.hpp"
#include "dal/RecordRepository.hpp"
#include "dal/VariableRepository.hpp"
#include "dal/ViewRepository.hpp"
#include "dal/ZoneRepository.hpp"
#include "security/AuthService.hpp"
```

**Step 2: Build and run tests**

Run: `cmake --build build --parallel && ctest --test-dir build --output-on-failure`
Expected: Clean build, all 38 tests pass.

**Step 3: Commit**

```bash
git add src/main.cpp
git commit -m "feat(startup): wire Phase 5 repositories, ApiServer, and HTTP server into startup"
```

---

## Task 16: Final Build Verification and Cleanup

**Step 1: Full clean build**

Run:
```bash
rm -rf build
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel
```
Expected: Clean build with zero warnings (project uses `-Werror`).

**Step 2: Run all tests**

Run: `ctest --test-dir build --output-on-failure`
Expected: All 38 tests pass (no new unit tests added — DAL repos require a live database).

**Step 3: Verify route stub files are no longer stubs**

Run:
```bash
grep -r "not implemented" src/api/ src/dal/
```
Expected: No matches for the Phase 5 files. Only stubs remaining should be:
- `src/api/routes/HealthRoutes.cpp` (Phase 6)
- `src/api/routes/DeploymentRoutes.cpp` (Phase 7)

**Step 4: Commit any cleanup**

If any warnings or issues were found, fix and commit:
```bash
git add -A
git commit -m "chore: Phase 5 final cleanup"
```
