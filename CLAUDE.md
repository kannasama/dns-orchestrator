# DNS Orchestrator — Claude Code Project Context

This file is read automatically by Claude Code at session start. It captures the project state,
architectural decisions, and development roadmap so context transfers across machines and sessions.

---

## Project Status

- **Phases 1–3 complete:** skeleton, foundation layer
- **Phase 3.5 complete:** HTTP library migration to Crow (CrowCpp v1.3.1)
- **Phase 4 complete:** Authentication & Authorisation (commit `efaa82f`)
- **Phase 5 complete:** DAL: Core Repositories + CRUD API Routes
- **Phase 6 complete:** PowerDNS Provider + Core Engines
- **Phase 7 complete:** Deployment Pipeline + GitOps
- **Phase 8 complete:** REST API Hardening + Docker Compose
- **Next task:** Phase 9
- **Tests:** 218 total (127 pass, 91 skip — DB integration tests need `DNS_DB_URL`)

Build and test:
```bash
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel
build/tests/dns-tests
```

Startup sequence: all steps wired in `src/main.cpp` (steps 1–12 complete).

---

## Tech Stack

| Component | Library |
|-----------|---------|
| Language | C++20 (`-Wall -Wextra -Wpedantic -Werror`) |
| Build | CMake 3.20+ + Ninja |
| HTTP server | **Crow/CrowCpp v1.3.1** via FetchContent |
| Database | PostgreSQL via libpqxx |
| Crypto | OpenSSL (AES-256-GCM, HMAC-SHA256 JWT) |
| Git integration | libgit2 |
| Logging | spdlog |
| JSON | nlohmann/json |
| Testing | Google Test + Google Mock (FetchContent) |

**HTTP library (Crow):** Header-only, FetchContent-compatible, Flask-like middleware API,
actively maintained (v1.3.1, Feb 2026).
- Route syntax: `CROW_ROUTE(app, "/api/v1/zones/<int>")(handler)`
- Middleware: structs with `before_handle()` / `after_handle()` methods

---

## Development Roadmap

### Phase 3.5 — HTTP Library Migration ← COMPLETE

**Summary:** Migrated HTTP library to Crow (CrowCpp v1.3.1) via CMake FetchContent. Pure
build/docs change — no HTTP framework types existed in source files, making the switch cost-free.

**Changes made:**
- `CMakeLists.txt` — added `FetchContent_MakeAvailable(Crow)` block
- `src/CMakeLists.txt` — added `target_link_libraries(dns-core PUBLIC Crow::Crow)`
- `include/api/ApiServer.hpp` — updated class comment to reference Crow application instance
- `docs/BUILD_ENVIRONMENT.md` — removed legacy AUR package; Crow is acquired at configure time
- `docs/ARCHITECTURE.md` + `docs/DESIGN.md` — updated all HTTP framework references to Crow

**Result:** Clean build, all 38 tests pass, zero framework references in source/cmake files.

---

### Phase 4 — Authentication & Authorisation ← COMPLETE

**Summary:** Production-grade auth layer with local login (Argon2id), JWT sessions, API key
authentication, role-based access control, and background maintenance tasks.

**Deliverables:**
- `src/security/AuthService.cpp` — `authenticateLocal()`, `validateToken()` with sliding + absolute TTL
- `src/security/SamlReplayCache.cpp` — in-memory replay detection with TTL eviction
- `src/dal/UserRepository.cpp` — `findByUsername()`, `findById()`, `create()`, `getHighestRole()`
- `src/dal/SessionRepository.cpp` — `create()`, `touch()`, `exists()`, `isValid()`,
  `deleteByHash()`, `pruneExpired()`
- `src/dal/ApiKeyRepository.cpp` — `create()`, `findByHash()`, `scheduleDelete()`, `pruneScheduled()`
- `src/api/AuthMiddleware.cpp` — dual-mode JWT + API key → `RequestContext`
- `src/api/routes/AuthRoutes.cpp` — `POST /login`, `POST /logout`, `GET /me`
- `src/core/MaintenanceScheduler.cpp` — jthread + condvar; session prune + API key cleanup
- `src/main.cpp` — wired startup steps 7a (MaintenanceScheduler) and 8 (SamlReplayCache)

**Tests:** 9 auth-related tests (unit + integration)

---

### Phase 5 — DAL: Core Repositories + CRUD API Routes ← COMPLETE

**Summary:** All remaining DAL repositories implemented with full CRUD. HTTP server starts and
serves requests. All entities persist to PostgreSQL with encrypted provider tokens.

**Deliverables:**
- `src/dal/ProviderRepository.cpp` — CRUD with `CryptoService::encrypt/decrypt` for tokens
- `src/dal/ViewRepository.cpp` — CRUD + `view_providers` attach/detach
- `src/dal/ZoneRepository.cpp` — CRUD with view FK, deployment retention
- `src/dal/RecordRepository.cpp` — CRUD with raw `{{var}}` templates
- `src/dal/VariableRepository.cpp` — CRUD with scope/zone logic, global uniqueness enforcement
- `src/dal/DeploymentRepository.cpp` — snapshot versioning with auto-seq + retention pruning
- `src/dal/AuditRepository.cpp` — append-only insert, dynamic query, purgeOld with self-audit
- `src/api/routes/ProviderRoutes.cpp` — 5 endpoints (GET list, POST, GET/{id}, PUT, DELETE)
- `src/api/routes/ViewRoutes.cpp` — 7 endpoints (CRUD + attach/detach providers)
- `src/api/routes/ZoneRoutes.cpp` — 5 endpoints (CRUD + view_id filter)
- `src/api/routes/RecordRoutes.cpp` — 5 endpoints (nested under /zones/{id}/records)
- `src/api/routes/VariableRoutes.cpp` — 5 endpoints (CRUD + scope/zone_id filters)
- `src/api/ApiServer.cpp` — registers all route classes, starts Crow HTTP server
- `src/main.cpp` — wired steps 10 (API routes) and 11 (HTTP server), signal handling,
  audit purge maintenance task

**Tests:** 86 new tests (7 repository suites + 1 CRUD routes suite, all DB-integration)

---

### Phase 6 — PowerDNS Provider + Core Engines ← COMPLETE

**Summary:** Connected to a real DNS provider (PowerDNS REST API v1), implemented variable
template expansion engine, and three-way diff computation between desired state and live
provider state.

**Deliverables:**
- `src/providers/PowerDnsProvider.cpp` — full PowerDNS REST API v1 client via cpp-httplib
- `src/providers/ProviderFactory.cpp` — creates `IProvider` instances by type string
- `src/core/VariableEngine.cpp` — `listDependencies()`, `expand()`, `validate()` for `{{var}}`
- `src/core/DiffEngine.cpp` — three-way diff → `PreviewResult` with drift detection
- `src/api/routes/HealthRoutes.cpp` — `GET /api/v1/health` (no auth required)
- `CMakeLists.txt` — added cpp-httplib v0.18.7 via FetchContent for HTTP client
- `src/main.cpp` — wired Step 9 (core engines), HealthRoutes into ApiServer

**Tests:** 35 new tests (8 VariableEngine unit, 9 VariableEngine integration, 4 ProviderFactory,
8 PowerDNS JSON parsing + record ID, 8 DiffEngine diff algorithm, -2 replaced placeholders)

---

### Phase 7 — Deployment Pipeline + GitOps ← COMPLETE

**Goal:** End-to-end zone push with audit trail and Git history.

**Deliverables:**
- `src/core/ThreadPool.cpp` — `std::jthread` pool, `submit()` → `std::future<T>` (6 unit tests)
- `src/dal/RecordRepository.cpp` — `deleteAllByZoneId()`, `upsertById()` for rollback support
- `src/gitops/GitOpsMirror.cpp` — `initialize()`, `commit()`, `pull()` via libgit2
- `src/core/DeploymentEngine.cpp` — lock → preview → push → audit → snapshot → GitOps
- `src/core/RollbackEngine.cpp` — full restore or cherry-pick from deployment snapshot
- `src/api/routes/RecordRoutes.cpp` — `POST /zones/{id}/preview`, `POST /zones/{id}/push`
- `src/api/routes/DeploymentRoutes.cpp` — history, snapshot diff, rollback endpoints
- `src/api/routes/AuditRoutes.cpp` — query, NDJSON export, purge endpoints
- `src/main.cpp` — all startup steps 1–12 wired (GitOpsMirror, ThreadPool, DeploymentEngine, RollbackEngine)

**Tests:** 180 total (89 pass, 91 skip — 17 new tests added in Phase 7)

---

### Phase 8 — REST API Hardening + Docker Compose ← COMPLETE

**Goal:** Full API surface documented and runnable in one command.

**Deliverables:**
- `src/api/RouteHelpers.cpp` — extracted shared `authenticate()`, `requireRole()`, `jsonResponse()`,
  `errorResponse()`, `invalidJsonResponse()` from all 9 route files
- `src/api/RequestValidator.cpp` — centralized input validation (15 methods, field length/format
  constraints from ARCHITECTURE.md §4.6.5)
- `src/api/RateLimiter.cpp` — token-bucket rate limiter (per-IP, thread-safe) wired into login
- Security response headers (X-Content-Type-Options, X-Frame-Options, Referrer-Policy, CSP)
  applied to all JSON responses via `applySecurityHeaders()`
- `include/common/Errors.hpp` — added `RateLimitedError` (429)
- `Dockerfile` — multi-stage build (debian:bookworm-slim builder → runtime)
- `docker-compose.yml` — PostgreSQL 16 + PowerDNS + app with health checks
- `.env.example` — documented environment variables
- `docs/openapi.yaml` — OpenAPI 3.1 spec covering all 24 endpoints
- `tests/integration/test_api_validation.cpp` — 13 API validation integration tests

**Tests:** 218 total (127 pass, 91 skip — 38 new tests added in Phase 8)

---

### Phase 9 — Web UI (Vue 3 + TypeScript)

Separate repository: `dns-orchestrator-ui`. Stack: Vite + Vue 3 + TypeScript.

Feature order: auth → providers → zones/views → records → variables → deployment workflow →
audit log.

---

### Phase 10 — Additional Providers

- `src/providers/CloudflareProvider.cpp` — Cloudflare API v4
- `src/providers/DigitalOceanProvider.cpp` — DigitalOcean API v2
- Provider-agnostic conformance test suite

---

### Phase 11 — TUI Client

Separate repository: `dns-orchestrator-tui`. Consumes REST API. See `docs/TUI_DESIGN.md`.

---

## Code Standards

**Naming (Hungarian notation variant):**

| Element | Convention | Example |
|---------|-----------|---------|
| Classes | PascalCase | `VariableEngine` |
| Instance vars | Abbr + PascalCase | `veEngine`, `cpPool` |
| Strings | `s` prefix | `sName`, `sZoneName` |
| Ints | `i` prefix | `iZoneId`, `iPort` |
| Bools | `b` prefix | `bHasDrift` |
| Vectors | `v` prefix | `vRecords` |
| Raw ptr (non-owning) | `p` prefix | `pService` |
| `shared_ptr` | `sp` prefix | `spEngine` |
| `unique_ptr` | `up` prefix | `upPool` |
| Member vars | `_` + type prefix | `_sUsername`, `_iPoolSize` |
| Functions | camelCase | `expand()`, `listRecords()` |
| Constants/enums | PascalCase | `HealthStatus::Degraded` |
| Namespaces | lowercase | `dns::core` |

**Formatting:** 2-space indent, 100-char line limit, Google style, K&R braces, `#pragma once`.

**Error handling:** `AppError` hierarchy; never catch and swallow silently; always map to HTTP
status. Business errors thrown as typed exceptions, caught at API boundary.

**Ownership:** `unique_ptr` by default; `shared_ptr` only when genuinely shared; raw pointers
only for non-owning references.

---

## Key File Paths

| Path | Purpose |
|------|---------|
| `docs/ARCHITECTURE.md` | Canonical design reference (86KB) |
| `docs/DESIGN.md` | Executive summary + design rationale |
| `docs/CODE_STANDARDS.md` | Full naming/formatting/ownership rules |
| `docs/TUI_DESIGN.md` | TUI client design spec |
| `scripts/db/001_initial_schema.sql` | Full PostgreSQL schema (11 tables) |
| `scripts/db/002_add_indexes.sql` | 11 performance indexes |
| `src/main.cpp` | Startup sequence (all steps 1–12 wired; Phase 8 complete) |
| `include/common/Types.hpp` | Core data types: `DnsRecord`, `PreviewResult`, `RequestContext` |
| `include/common/Errors.hpp` | `AppError` hierarchy (incl. `RateLimitedError` 429) |
| `include/api/RouteHelpers.hpp` | Shared route helpers (auth, response, security headers) |
| `include/api/RequestValidator.hpp` | Input validation (field length/format constraints) |
| `include/api/RateLimiter.hpp` | Token-bucket rate limiter for auth endpoints |
| `docs/openapi.yaml` | OpenAPI 3.1 specification (24 endpoints) |
| `Dockerfile` | Multi-stage build (builder → runtime) |
| `docker-compose.yml` | PostgreSQL 16 + PowerDNS + app |
| `tests/unit/` | Unit tests (MaintenanceScheduler, SamlReplayCache, JWT, Crypto, RouteHelpers, RequestValidator, RateLimiter) |
| `tests/integration/` | Integration tests (AuthService, AuthMiddleware, repositories, API validation) |
