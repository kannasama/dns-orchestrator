# Phase 5 — DAL: Core Repositories + CRUD API Routes

## Context

Phase 4 delivered a production-grade auth layer (Argon2id, JWT, API keys, RBAC middleware,
MaintenanceScheduler). All stubs for Phase 5 entities exist as empty classes with default
constructors. The database schema (`001_initial_schema.sql`) and indexes (`002_add_indexes.sql`)
are already in place. CMake auto-discovers source and test files via `GLOB_RECURSE`.

**Goal:** Implement all remaining DAL repositories and wire CRUD API routes so the application
can store and retrieve real data. The HTTP server starts and serves requests by the end of this
phase.

---

## Execution Order

Build bottom-up: repositories first (no API dependency), then route handlers, then `ApiServer`
wiring, then `src/main.cpp` startup integration. Each step is independently compilable and
testable.

---

## Step 1: ProviderRepository

**Files:**
- `include/dal/ProviderRepository.hpp` — replace stub with full class
- `src/dal/ProviderRepository.cpp` — implement all methods
- `tests/integration/test_provider_repository.cpp` — new

**Header design:**

```cpp
#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace dns::dal {

class ConnectionPool;

namespace dns::security {
class CryptoService;
}

struct ProviderRow {
  int64_t iId = 0;
  std::string sName;
  std::string sType;           // 'powerdns', 'cloudflare', 'digitalocean'
  std::string sApiEndpoint;
  std::string sDecryptedToken; // plaintext — decrypted on read
  std::chrono::system_clock::time_point tpCreatedAt;
  std::chrono::system_clock::time_point tpUpdatedAt;
};

class ProviderRepository {
 public:
  ProviderRepository(ConnectionPool& cpPool,
                     const dns::security::CryptoService& csService);
  ~ProviderRepository();

  int64_t create(const std::string& sName, const std::string& sType,
                 const std::string& sApiEndpoint, const std::string& sPlaintextToken);

  std::vector<ProviderRow> listAll();

  std::optional<ProviderRow> findById(int64_t iId);

  void update(int64_t iId, const std::string& sName, const std::string& sApiEndpoint,
              const std::optional<std::string>& oPlaintextToken);

  void deleteById(int64_t iId);

 private:
  ConnectionPool& _cpPool;
  const dns::security::CryptoService& _csService;

  ProviderRow mapRow(const pqxx::row& row) const;
};

}  // namespace dns::dal
```

**Implementation notes:**
- Constructor takes `ConnectionPool&` and `const CryptoService&` (non-owning refs).
- `create()` calls `_csService.encrypt(sPlaintextToken)` before INSERT; returns BIGSERIAL id.
- `listAll()` and `findById()` call `_csService.decrypt()` on `encrypted_token` column.
- `update()` only re-encrypts if `oPlaintextToken.has_value()`.
- `deleteById()` executes `DELETE FROM providers WHERE id = $1`. FK on `view_providers` uses
  `ON DELETE CASCADE` so no manual cleanup needed.
- On duplicate name → catch `pqxx::unique_violation` → throw `ConflictError("PROVIDER_EXISTS")`.
- On not found → throw `NotFoundError("PROVIDER_NOT_FOUND")`.
- Private `mapRow()` helper decrypts token and parses timestamps via
  `EXTRACT(EPOCH FROM ...)::bigint`.

**Tests (integration, skip without `DNS_DB_URL`):**
- `CreateAndFindById` — roundtrip create → find; verify decrypted token matches plaintext.
- `ListAll` — create 2 providers, verify list returns both.
- `UpdateWithToken` — update name + token, verify new values persist.
- `UpdateWithoutToken` — update name only, verify token unchanged.
- `DeleteById` — delete, verify findById returns nullopt.
- `DuplicateNameThrows` — create two with same name, expect `ConflictError`.

---

## Step 2: ViewRepository

**Files:**
- `include/dal/ViewRepository.hpp` — replace stub
- `src/dal/ViewRepository.cpp` — implement
- `tests/integration/test_view_repository.cpp` — new

**Header design:**

```cpp
struct ViewRow {
  int64_t iId = 0;
  std::string sName;
  std::string sDescription;
  std::chrono::system_clock::time_point tpCreatedAt;
  std::vector<int64_t> vProviderIds;  // populated by findWithProviders()
};

class ViewRepository {
 public:
  explicit ViewRepository(ConnectionPool& cpPool);
  ~ViewRepository();

  int64_t create(const std::string& sName, const std::string& sDescription);
  std::vector<ViewRow> listAll();
  std::optional<ViewRow> findById(int64_t iId);
  std::optional<ViewRow> findWithProviders(int64_t iId);
  void update(int64_t iId, const std::string& sName, const std::string& sDescription);
  void deleteById(int64_t iId);

  void attachProvider(int64_t iViewId, int64_t iProviderId);
  void detachProvider(int64_t iViewId, int64_t iProviderId);

 private:
  ConnectionPool& _cpPool;
};
```

**Implementation notes:**
- `findById()` queries `views` only (no join). `vProviderIds` left empty.
- `findWithProviders()` LEFT JOINs `view_providers` to populate `vProviderIds`.
- `attachProvider()` inserts into `view_providers`; catches `unique_violation` as no-op
  (idempotent). Catches foreign key violation → `NotFoundError`.
- `detachProvider()` deletes from `view_providers`. Silent no-op if row doesn't exist.
- `deleteById()` cascades to `view_providers`. Throws `NotFoundError` if 0 rows affected.
  Note: zones FK is `ON DELETE RESTRICT` — if zones reference this view, PostgreSQL will reject
  the delete. Catch `pqxx::foreign_key_violation` → throw `ConflictError("VIEW_HAS_ZONES")`.

**Tests:**
- `CreateAndFindById` — roundtrip.
- `FindWithProviders` — create view, attach 2 providers, verify `vProviderIds`.
- `AttachDetach` — attach, verify, detach, verify empty.
- `DeleteCascadesViewProviders` — delete view, verify view_providers rows gone.
- `DeleteBlockedByZones` — create zone referencing view, expect `ConflictError` on delete.
- `DuplicateNameThrows` — expect `ConflictError`.

---

## Step 3: ZoneRepository

**Files:**
- `include/dal/ZoneRepository.hpp` — replace stub
- `src/dal/ZoneRepository.cpp` — implement
- `tests/integration/test_zone_repository.cpp` — new

**Header design:**

```cpp
struct ZoneRow {
  int64_t iId = 0;
  std::string sName;
  int64_t iViewId = 0;
  std::optional<int> oDeploymentRetention;
  std::chrono::system_clock::time_point tpCreatedAt;
};

class ZoneRepository {
 public:
  explicit ZoneRepository(ConnectionPool& cpPool);
  ~ZoneRepository();

  int64_t create(const std::string& sName, int64_t iViewId,
                 std::optional<int> oRetention);
  std::vector<ZoneRow> listAll();
  std::vector<ZoneRow> listByViewId(int64_t iViewId);
  std::optional<ZoneRow> findById(int64_t iId);
  void update(int64_t iId, const std::string& sName, std::optional<int> oRetention);
  void deleteById(int64_t iId);

 private:
  ConnectionPool& _cpPool;
};
```

**Implementation notes:**
- UNIQUE constraint is `(name, view_id)` — same zone name allowed in different views.
- `create()` catches `pqxx::foreign_key_violation` on invalid `iViewId` →
  `ValidationError("INVALID_VIEW_ID")`.
- `deleteById()` cascades to records, variables, deployments (all `ON DELETE CASCADE`).
- `update()` does NOT allow changing `view_id` (architectural decision — move = delete + recreate).

**Tests:**
- `CreateAndFindById` — roundtrip with retention.
- `ListByViewId` — create zones in 2 views, filter by one.
- `DuplicateNameSameViewThrows` — same (name, view_id) pair, expect `ConflictError`.
- `SameNameDifferentViewAllowed` — same name, different views, both succeed.
- `DeleteCascades` — delete zone, verify records/variables/deployments gone.
- `InvalidViewIdThrows` — non-existent view_id, expect `ValidationError`.

---

## Step 4: RecordRepository

**Files:**
- `include/dal/RecordRepository.hpp` — replace stub
- `src/dal/RecordRepository.cpp` — implement
- `tests/integration/test_record_repository.cpp` — new

**Header design:**

```cpp
struct RecordRow {
  int64_t iId = 0;
  int64_t iZoneId = 0;
  std::string sName;
  std::string sType;
  int iTtl = 300;
  std::string sValueTemplate;     // raw template, may contain {{var_name}}
  int iPriority = 0;
  std::optional<int64_t> oLastAuditId;
  std::chrono::system_clock::time_point tpCreatedAt;
  std::chrono::system_clock::time_point tpUpdatedAt;
};

class RecordRepository {
 public:
  explicit RecordRepository(ConnectionPool& cpPool);
  ~RecordRepository();

  int64_t create(int64_t iZoneId, const std::string& sName, const std::string& sType,
                 int iTtl, const std::string& sValueTemplate, int iPriority);
  std::vector<RecordRow> listByZoneId(int64_t iZoneId);
  std::optional<RecordRow> findById(int64_t iId);
  void update(int64_t iId, const std::string& sName, const std::string& sType,
              int iTtl, const std::string& sValueTemplate, int iPriority);
  void deleteById(int64_t iId);

 private:
  ConnectionPool& _cpPool;
};
```

**Implementation notes:**
- Records store raw templates. Variable expansion is Phase 6 (`VariableEngine`).
- `create()` sets `updated_at = NOW()` implicitly via schema default.
- `update()` sets `updated_at = NOW()` explicitly in the UPDATE statement.
- `deleteById()` throws `NotFoundError` if 0 rows affected.
- No unique constraint beyond PK — same (name, type) pair is allowed (e.g., multiple A records).

**Tests:**
- `CreateAndFindById` — roundtrip with template value `{{LB_VIP}}`.
- `ListByZoneId` — create records in 2 zones, filter by one.
- `Update` — change TTL and value_template, verify.
- `DeleteById` — delete, verify gone.
- `InvalidZoneIdThrows` — FK violation on nonexistent zone.

---

## Step 5: VariableRepository

**Files:**
- `include/dal/VariableRepository.hpp` — replace stub
- `src/dal/VariableRepository.cpp` — implement
- `tests/integration/test_variable_repository.cpp` — new

**Header design:**

```cpp
struct VariableRow {
  int64_t iId = 0;
  std::string sName;
  std::string sValue;
  std::string sType;        // 'ipv4', 'ipv6', 'target', 'string'
  std::string sScope;       // 'global', 'zone'
  std::optional<int64_t> oZoneId;
  std::chrono::system_clock::time_point tpCreatedAt;
  std::chrono::system_clock::time_point tpUpdatedAt;
};

class VariableRepository {
 public:
  explicit VariableRepository(ConnectionPool& cpPool);
  ~VariableRepository();

  int64_t create(const std::string& sName, const std::string& sValue,
                 const std::string& sType, const std::string& sScope,
                 std::optional<int64_t> oZoneId);
  std::vector<VariableRow> listAll();
  std::vector<VariableRow> listByScope(const std::string& sScope);
  std::vector<VariableRow> listByZoneId(int64_t iZoneId);
  std::optional<VariableRow> findById(int64_t iId);
  void update(int64_t iId, const std::string& sValue);
  void deleteById(int64_t iId);

 private:
  ConnectionPool& _cpPool;
};
```

**Implementation notes:**
- DB CHECK constraint enforces: `scope = 'global' AND zone_id IS NULL` OR
  `scope = 'zone' AND zone_id IS NOT NULL`. Catch `pqxx::check_violation` →
  `ValidationError("SCOPE_ZONE_MISMATCH")`.
- UNIQUE constraint on `(name, zone_id)`. Global vars have `zone_id = NULL` — PostgreSQL's
  UNIQUE treats NULL as distinct, so two globals with the same name would NOT violate the
  constraint. Handle this in application logic: before creating a global variable, check if one
  with the same name already exists (WHERE name = $1 AND zone_id IS NULL).
- `update()` only changes `value` and `updated_at`. Name, type, scope are immutable after
  creation (delete + recreate to change).
- `listByZoneId()` returns zone-scoped vars for that zone AND all global vars (both needed for
  variable expansion in Phase 6).

**Tests:**
- `CreateGlobalAndFind` — global var roundtrip.
- `CreateZoneScopedAndFind` — zone-scoped var roundtrip.
- `ListByZoneIdIncludesGlobals` — create global + zone var, list by zone, verify both returned.
- `ListByScope` — filter global-only.
- `UpdateValue` — change value, verify.
- `ScopeMismatchThrows` — scope='global' with zone_id set, expect `ValidationError`.
- `DuplicateNameSameZoneThrows` — expect `ConflictError`.

---

## Step 6: DeploymentRepository

**Files:**
- `include/dal/DeploymentRepository.hpp` — replace stub
- `src/dal/DeploymentRepository.cpp` — implement
- `tests/integration/test_deployment_repository.cpp` — new

**Header design:**

```cpp
struct DeploymentRow {
  int64_t iId = 0;
  int64_t iZoneId = 0;
  int64_t iDeployedByUserId = 0;
  std::chrono::system_clock::time_point tpDeployedAt;
  int64_t iSeq = 0;
  nlohmann::json jSnapshot;
};

class DeploymentRepository {
 public:
  explicit DeploymentRepository(ConnectionPool& cpPool);
  ~DeploymentRepository();

  int64_t create(int64_t iZoneId, int64_t iDeployedByUserId,
                 const nlohmann::json& jSnapshot);
  std::vector<DeploymentRow> listByZoneId(int64_t iZoneId, int iLimit = 50);
  std::optional<DeploymentRow> findById(int64_t iId);
  int pruneByRetention(int64_t iZoneId, int iRetentionCount);

 private:
  ConnectionPool& _cpPool;
};
```

**Implementation notes:**
- `create()` auto-generates `seq` via subquery:
  `COALESCE((SELECT MAX(seq) FROM deployments WHERE zone_id = $1), 0) + 1`.
  This runs inside the same transaction to prevent races.
- `listByZoneId()` orders by `seq DESC` with LIMIT.
- `pruneByRetention()` keeps the N most recent deployments (by seq), deletes the rest.
  Returns count of deleted rows. Uses:
  `DELETE FROM deployments WHERE zone_id = $1 AND seq <= (SELECT MAX(seq) - $2 FROM deployments WHERE zone_id = $1)`.
- Snapshot is stored/retrieved as `nlohmann::json` ↔ `JSONB` column. Use `.dump()` on write,
  `nlohmann::json::parse()` on read.

**Tests:**
- `CreateAndFindById` — roundtrip with JSON snapshot.
- `SeqAutoIncrements` — create 3 deployments, verify seq 1, 2, 3.
- `ListByZoneIdOrdered` — verify DESC order.
- `PruneByRetention` — create 5, prune to 3, verify only last 3 remain.

---

## Step 7: AuditRepository

**Files:**
- `include/dal/AuditRepository.hpp` — replace stub (keep existing `PurgeResult` struct)
- `src/dal/AuditRepository.cpp` — implement
- `tests/integration/test_audit_repository.cpp` — new

**Header design:**

```cpp
struct AuditLogRow {
  int64_t iId = 0;
  std::string sEntityType;
  std::optional<int64_t> oEntityId;
  std::string sOperation;
  std::optional<nlohmann::json> ojOldValue;
  std::optional<nlohmann::json> ojNewValue;
  std::optional<std::string> osVariableUsed;
  std::string sIdentity;
  std::optional<std::string> osAuthMethod;
  std::optional<std::string> osIpAddress;
  std::chrono::system_clock::time_point tpTimestamp;
};

// PurgeResult already exists in the stub header

class AuditRepository {
 public:
  explicit AuditRepository(ConnectionPool& cpPool);
  ~AuditRepository();

  int64_t insert(const std::string& sEntityType, std::optional<int64_t> oEntityId,
                 const std::string& sOperation,
                 const std::optional<nlohmann::json>& ojOldValue,
                 const std::optional<nlohmann::json>& ojNewValue,
                 const std::string& sIdentity,
                 const std::optional<std::string>& osAuthMethod,
                 const std::optional<std::string>& osIpAddress);

  std::vector<AuditLogRow> query(
      const std::optional<std::string>& osEntityType,
      const std::optional<int64_t>& oEntityId,
      const std::optional<std::string>& osIdentity,
      const std::optional<std::chrono::system_clock::time_point>& otpFrom,
      const std::optional<std::chrono::system_clock::time_point>& otpTo,
      int iLimit = 100);

  PurgeResult purgeOld(int iRetentionDays);

 private:
  ConnectionPool& _cpPool;
};
```

**Implementation notes:**
- `insert()` is the primary write path. Returns the `BIGSERIAL` id.
- `query()` builds a dynamic WHERE clause based on which optionals are present. Uses
  parameterised queries (never string interpolation). Orders by `timestamp DESC`.
- `purgeOld()` deletes rows where `timestamp < NOW() - interval '$1 days'`. Returns
  `PurgeResult{iDeletedCount, oOldestRemaining}`. After purging, inserts a system audit entry
  recording the purge operation.
- NDJSON export (`exportNdjson`) is deferred to Phase 7's `AuditRoutes` — not needed for basic
  CRUD.

**Tests:**
- `InsertAndQuery` — insert an audit entry, query by entity_type, verify returned.
- `QueryFilters` — insert multiple entries, filter by identity and date range.
- `PurgeOld` — insert old entry (requires manual timestamp override via raw SQL in setup),
  purge, verify deleted.

---

## Step 8: CRUD Route Handlers

Implement route handlers for providers, views, zones, records, and variables. Each route class
follows the `AuthRoutes` pattern: constructor takes repository + middleware refs, `registerRoutes()`
registers lambdas on `crow::SimpleApp&`.

### Step 8a: ProviderRoutes

**Files:**
- `include/api/routes/ProviderRoutes.hpp` — replace stub
- `src/api/routes/ProviderRoutes.cpp` — implement

**Routes:**

| Method | Path | Role | Handler |
|--------|------|------|---------|
| GET | `/api/v1/providers` | viewer | `listAll()` — returns JSON array (token field omitted) |
| POST | `/api/v1/providers` | admin | `create()` — body: `{name, type, api_endpoint, token}` |
| GET | `/api/v1/providers/<int>` | viewer | `findById()` — returns full provider (token included) |
| PUT | `/api/v1/providers/<int>` | admin | `update()` — body: `{name, api_endpoint, token?}` |
| DELETE | `/api/v1/providers/<int>` | admin | `deleteById()` |

**Design notes:**
- Constructor: `ProviderRoutes(ProviderRepository&, const AuthMiddleware&)`.
- Every handler calls `_amMiddleware.authenticate(...)` first.
- Role check: compare `rcCtx.sRole` against required role. Throw
  `AuthorizationError("INSUFFICIENT_ROLE")` if viewer tries admin-only action.
- `GET /providers` (list) omits the `token` field from the response (security: don't leak tokens
  in bulk listing). `GET /providers/{id}` includes it (needed for admin review).
- JSON parse errors → 400 with `{"error": "invalid_json"}`.
- `AppError` subclasses caught at handler boundary → mapped to HTTP status.

### Step 8b: ViewRoutes

**Files:**
- `include/api/routes/ViewRoutes.hpp` — replace stub
- `src/api/routes/ViewRoutes.cpp` — implement

**Routes:**

| Method | Path | Role | Handler |
|--------|------|------|---------|
| GET | `/api/v1/views` | viewer | `listAll()` |
| POST | `/api/v1/views` | admin | `create()` — body: `{name, description}` |
| GET | `/api/v1/views/<int>` | viewer | `findWithProviders()` — includes `provider_ids` |
| PUT | `/api/v1/views/<int>` | admin | `update()` |
| DELETE | `/api/v1/views/<int>` | admin | `deleteById()` |
| POST | `/api/v1/views/<int>/providers/<int>` | admin | `attachProvider()` |
| DELETE | `/api/v1/views/<int>/providers/<int>` | admin | `detachProvider()` |

### Step 8c: ZoneRoutes

**Files:**
- `include/api/routes/ZoneRoutes.hpp` — replace stub
- `src/api/routes/ZoneRoutes.cpp` — implement

**Routes:**

| Method | Path | Role | Handler |
|--------|------|------|---------|
| GET | `/api/v1/zones` | viewer | `listAll()` or `listByViewId()` if `?view_id=` present |
| POST | `/api/v1/zones` | admin | `create()` — body: `{name, view_id, deployment_retention?}` |
| GET | `/api/v1/zones/<int>` | viewer | `findById()` |
| PUT | `/api/v1/zones/<int>` | admin | `update()` — body: `{name, deployment_retention?}` |
| DELETE | `/api/v1/zones/<int>` | admin | `deleteById()` |

### Step 8d: RecordRoutes

**Files:**
- `include/api/routes/RecordRoutes.hpp` — replace stub
- `src/api/routes/RecordRoutes.cpp` — implement

**Routes:**

| Method | Path | Role | Handler |
|--------|------|------|---------|
| GET | `/api/v1/zones/<int>/records` | viewer | `listByZoneId()` |
| POST | `/api/v1/zones/<int>/records` | operator | `create()` |
| GET | `/api/v1/zones/<int>/records/<int>` | viewer | `findById()` |
| PUT | `/api/v1/zones/<int>/records/<int>` | operator | `update()` |
| DELETE | `/api/v1/zones/<int>/records/<int>` | operator | `deleteById()` |

**Note:** Preview and push endpoints are Phase 6/7 — only CRUD here.

### Step 8e: VariableRoutes

**Files:**
- `include/api/routes/VariableRoutes.hpp` — replace stub
- `src/api/routes/VariableRoutes.cpp` — implement

**Routes:**

| Method | Path | Role | Handler |
|--------|------|------|---------|
| GET | `/api/v1/variables` | viewer | `listAll()`, `listByScope()`, or `listByZoneId()` based on query params |
| POST | `/api/v1/variables` | operator | `create()` — body: `{name, value, type, scope, zone_id?}` |
| GET | `/api/v1/variables/<int>` | viewer | `findById()` |
| PUT | `/api/v1/variables/<int>` | operator | `update()` — body: `{value}` |
| DELETE | `/api/v1/variables/<int>` | operator | `deleteById()` |

---

## Step 9: ApiServer + HTTP Startup

**Files:**
- `include/api/ApiServer.hpp` — replace stub with full class
- `src/api/ApiServer.cpp` — implement

**Design:**

```cpp
class ApiServer {
 public:
  ApiServer(crow::SimpleApp& app, const AuthMiddleware& amMiddleware,
            AuthRoutes& arRoutes, ProviderRoutes& prRoutes,
            ViewRoutes& vrRoutes, ZoneRoutes& zrRoutes,
            RecordRoutes& rrRoutes, VariableRoutes& varRoutes);
  ~ApiServer();

  void registerRoutes();
  void start(int iPort, int iThreads);
  void stop();

 private:
  crow::SimpleApp& _app;
  // ... refs to all route classes
};
```

**Implementation notes:**
- `registerRoutes()` calls `registerRoutes(app)` on each route class.
- `start()` calls `_app.port(iPort).multithreaded().concurrency(iThreads).run()`.
  Crow's `run()` blocks — it should be called on the main thread.
- `stop()` calls `_app.stop()`.
- Deployment/Audit routes remain stubs (Phase 7) — do NOT register them yet.

---

## Step 10: Startup Integration (`src/main.cpp`)

**Changes:**
- After step 8 (SamlReplayCache), construct all Phase 5 repositories:
  - `ProviderRepository` (needs `cpPool` + `csService`)
  - `ViewRepository`, `ZoneRepository`, `RecordRepository`, `VariableRepository` (need `cpPool`)
  - `DeploymentRepository`, `AuditRepository` (need `cpPool`)
- Construct `AuthMiddleware`, `AuthService` (already exist).
- Construct all route classes with their dependencies.
- Construct `ApiServer` with `crow::SimpleApp` and all route classes.
- Call `apiServer.registerRoutes()`.
- Wire step 10 (API routes registered) and step 11 (HTTP server start).
- Replace the immediate `msScheduler->stop()` / `return EXIT_SUCCESS` with
  `apiServer.start(cfgApp.iHttpPort, cfgApp.iHttpThreads)` which blocks on the Crow event loop.
- Set up signal handling: on SIGINT/SIGTERM, call `apiServer.stop()` then
  `msScheduler->stop()` for graceful shutdown.
- Schedule `auditRepository.purgeOld()` as a maintenance task (interval:
  `cfgApp.iAuditPurgeIntervalSeconds`).

**Deferred startup steps (still warn-logged):**
- Step 6: GitOpsMirror → Phase 7
- Step 7: ThreadPool → Phase 7
- Step 9: ProviderFactory → Phase 6
- Step 12: Background task queue → Phase 7

---

## Step 11: Integration Tests for Routes

**File:** `tests/integration/test_crud_routes.cpp` (or per-resource files)

These tests verify the full HTTP roundtrip using Crow's built-in test client or by
constructing the route classes directly and calling handler lambdas.

**Strategy:** Since Crow routes register lambdas that capture `this`, we can test at the
route-handler level by constructing repositories with a real DB and calling the handler methods.
Alternatively, use Crow's `app.handle(req, res)` for integration-level testing.

**Minimum coverage:**
- Provider CRUD: create → get → list → update → delete
- View CRUD: create → attach provider → get with providers → detach → delete
- Zone CRUD: create → get → list by view → update → delete
- Record CRUD: create → list by zone → update → delete
- Variable CRUD: create global → create zone-scoped → list by zone → update → delete
- Auth enforcement: 401 without token, 403 with viewer on admin route

---

## Step 12: Update CLAUDE.md

Update `CLAUDE.md` to reflect Phase 5 completion:
- Mark Phase 5 as complete in Project Status
- Update startup sequence status (steps 10, 11 now done)
- Update test counts
- Add summary of Phase 5 deliverables

---

## Verification

After all steps are complete:

```bash
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

- All existing tests still pass (39 pass, 4 skip).
- New repository integration tests pass when `DNS_DB_URL` is set.
- HTTP server starts on configured port.
- `POST /api/v1/providers` with valid JWT creates a provider and returns 201.
- `GET /api/v1/providers` returns the created provider.
- `GET /api/v1/providers/{id}` returns the provider with decrypted token.
- All CRUD endpoints for views, zones, records, variables work end-to-end.
- 401 returned on any protected route without token.
- 403 returned when viewer attempts admin-only operation.

---

## Dependencies Between Steps

```
Steps 1-7 (repositories) — independent of each other, can be parallelised
    │
    ├── Step 8a-8e (route handlers) — each depends on its repository step
    │
    ├── Step 9 (ApiServer) — depends on all route handler steps
    │
    └── Step 10 (main.cpp) — depends on Step 9
         │
         └── Step 11 (integration tests) — depends on Step 10
              │
              └── Step 12 (CLAUDE.md update)
```

Repositories (Steps 1-7) should be built in the listed order due to FK dependencies in tests
(providers needed for view tests, views needed for zone tests, zones needed for record/variable
tests, etc.), but the implementations themselves are independent.

---

## Files Modified/Created Summary

**Headers modified (6 — replacing stubs):**
- `include/dal/ProviderRepository.hpp`
- `include/dal/ViewRepository.hpp`
- `include/dal/ZoneRepository.hpp`
- `include/dal/RecordRepository.hpp`
- `include/dal/VariableRepository.hpp`
- `include/dal/DeploymentRepository.hpp`
- `include/dal/AuditRepository.hpp`

**Headers modified (6 — replacing stubs):**
- `include/api/routes/ProviderRoutes.hpp`
- `include/api/routes/ViewRoutes.hpp`
- `include/api/routes/ZoneRoutes.hpp`
- `include/api/routes/RecordRoutes.hpp`
- `include/api/routes/VariableRoutes.hpp`
- `include/api/ApiServer.hpp`

**Implementations modified (13 — replacing stubs):**
- `src/dal/ProviderRepository.cpp`
- `src/dal/ViewRepository.cpp`
- `src/dal/ZoneRepository.cpp`
- `src/dal/RecordRepository.cpp`
- `src/dal/VariableRepository.cpp`
- `src/dal/DeploymentRepository.cpp`
- `src/dal/AuditRepository.cpp`
- `src/api/routes/ProviderRoutes.cpp`
- `src/api/routes/ViewRoutes.cpp`
- `src/api/routes/ZoneRoutes.cpp`
- `src/api/routes/RecordRoutes.cpp`
- `src/api/routes/VariableRoutes.cpp`
- `src/api/ApiServer.cpp`

**Startup modified (1):**
- `src/main.cpp`

**Tests created (8+):**
- `tests/integration/test_provider_repository.cpp`
- `tests/integration/test_view_repository.cpp`
- `tests/integration/test_zone_repository.cpp`
- `tests/integration/test_record_repository.cpp`
- `tests/integration/test_variable_repository.cpp`
- `tests/integration/test_deployment_repository.cpp`
- `tests/integration/test_audit_repository.cpp`
- `tests/integration/test_crud_routes.cpp`

**Documentation updated (1):**
- `CLAUDE.md`

**No CMake changes needed** — `GLOB_RECURSE` auto-discovers new source and test files.
