# Architecture: C++ Multi-Provider DNS Orchestrator

> This document translates the design intent of [SPEC.md](SPEC.md) into a concrete, implementable system architecture. It defines component boundaries, interfaces, data models, API contracts, and data flows.

---

## Table of Contents

1. [Guiding Principles](#1-guiding-principles)
2. [System Context](#2-system-context)
3. [Layer Decomposition](#3-layer-decomposition)
4. [Component Descriptions](#4-component-descriptions)
   - 4.1 [HTTP API Server Layer](#41-http-api-server-layer)
   - 4.2 [Core Engine](#42-core-engine)
   - 4.3 [Provider Abstraction Layer](#43-provider-abstraction-layer)
   - 4.4 [Data Access Layer](#44-data-access-layer)
   - 4.5 [GitOps Mirror Subsystem](#45-gitops-mirror-subsystem)
   - 4.6 [Security Subsystem](#46-security-subsystem)
   - 4.7 [TUI Layer](#47-tui-layer)
   - 4.8 [Thread Pool and Concurrency Model](#48-thread-pool-and-concurrency-model)
5. [PostgreSQL Schema](#5-postgresql-schema)
6. [REST API Contract](#6-rest-api-contract)
7. [Data Flow Diagrams](#7-data-flow-diagrams)
   - 7.1 [Staging → Preview → Deploy Pipeline](#71-staging--preview--deploy-pipeline)
   - 7.2 [Variable Expansion Flow](#72-variable-expansion-flow)
   - 7.3 [GitOps Mirror Flow](#73-gitops-mirror-flow)
   - 7.4 [Authentication Flow](#74-authentication-flow)
8. [Configuration and Environment Variables](#8-configuration-and-environment-variables)
9. [Error Taxonomy and Handling Strategy](#9-error-taxonomy-and-handling-strategy)
10. [Directory and File Structure](#10-directory-and-file-structure)
11. [Dockerfile and Deployment Model](#11-dockerfile-and-deployment-model)

---

## 1. Guiding Principles

| Principle | Application |
|-----------|-------------|
| **Single Source of Truth** | PostgreSQL is the authoritative state store; providers are downstream targets |
| **Fail-Safe Deployments** | No push occurs unless variable expansion and diff preview succeed without errors |
| **Provider Isolation** | Internal-view records are never transmitted to external-view providers |
| **Abstraction at Boundaries** | All provider, HTTP, and storage integrations are hidden behind C++ abstract interfaces |
| **Simplicity First** | Restbed is used directly; an `IHttpServer` wrapper is provided only if a second framework is ever needed |
| **Auditability** | Every mutation is logged with full before/after state and actor identity |
| **GitOps as Mirror** | Git is a human-readable backup of live state, not a source of truth |

---

## 2. System Context

```
┌──────────────────────────────────────────────────────────────────────┐
│                          Operators / Users                           │
│              (Web Browser)              (Terminal / SSH)             │
└────────────────────┬─────────────────────────────┬───────────────────┘
                     │ HTTPS                        │ stdin/stdout
          ┌──────────▼──────────┐        ┌──────────▼──────────┐
          │     Web GUI         │        │        TUI           │
          │  (served by API)    │        │      (FTXUI)         │
          └──────────┬──────────┘        └──────────┬──────────┘
                     │                              │
          ┌──────────▼──────────────────────────────▼──────────┐
          │              REST API Server (Restbed)              │
          │                  /api/v1/...                        │
          └──────────────────────────┬──────────────────────────┘
                                     │
          ┌──────────────────────────▼──────────────────────────┐
          │                    Core Engine                       │
          │   Variable Engine | Diff Engine | Deployment Engine  │
          └──────┬──────────────────────────────────┬───────────┘
                 │                                  │
   ┌─────────────▼──────────┐          ┌────────────▼────────────┐
   │  Data Access Layer     │          │  Provider Abstraction   │
   │  (libpqxx / PostgreSQL)│          │  (IProvider interface)  │
   └─────────────┬──────────┘          └────────────┬────────────┘
                 │                                  │
   ┌─────────────▼──────────┐     ┌─────────────────▼──────────────────┐
   │     PostgreSQL 15+     │     │  PowerDNS | Cloudflare | DigitalOcean│
   └────────────────────────┘     └────────────────────────────────────┘
                 │
   ┌─────────────▼──────────┐
   │  GitOps Mirror         │
   │  (libgit2 / bare repo) │
   └────────────────────────┘
```

---

## 3. Layer Decomposition

The codebase is organized into six horizontal layers. Each layer may only depend on layers below it.

```
┌─────────────────────────────────────────────────────────┐  Layer 6
│  Client Layer:  Web GUI static assets  |  TUI (FTXUI)   │
├─────────────────────────────────────────────────────────┤  Layer 5
│  API Layer:     Restbed HTTP handlers  |  Route mapping  │
├─────────────────────────────────────────────────────────┤  Layer 4
│  Core Engine:   VariableEngine  |  DiffEngine           │
│                 DeploymentEngine  |  ThreadPool          │
├─────────────────────────────────────────────────────────┤  Layer 3
│  Provider Layer:  IProvider  |  PowerDnsProvider        │
│                   CloudflareProvider  |  DoProvider      │
├─────────────────────────────────────────────────────────┤  Layer 2
│  Data Access Layer:  Repository classes  |  Migrations   │
├─────────────────────────────────────────────────────────┤  Layer 1
│  Infrastructure:  PostgreSQL  |  libgit2  |  OpenSSL    │
└─────────────────────────────────────────────────────────┘
```

Cross-cutting concerns (logging, error types, configuration) live in a `common/` module that all layers may use.

---

## 4. Component Descriptions

### 4.1 HTTP API Server Layer

**Framework:** Restbed (via `librestbed`)

**Responsibilities:**
- Parse and validate incoming HTTP requests
- Authenticate requests via the Security Subsystem (JWT bearer token check)
- Dispatch to Core Engine or DAL service methods
- Serialize responses as JSON (`nlohmann/json`, 4-space indent)
- Return structured error responses (see §9)

**Key Classes:**

| Class | Header | Responsibility |
|-------|--------|----------------|
| `ApiServer` | `api/ApiServer.hpp` | Owns the `restbed::Service` instance; registers all routes at startup |
| `ProviderRoutes` | `api/routes/ProviderRoutes.hpp` | Handlers for `/api/v1/providers` |
| `ViewRoutes` | `api/routes/ViewRoutes.hpp` | Handlers for `/api/v1/views` |
| `ZoneRoutes` | `api/routes/ZoneRoutes.hpp` | Handlers for `/api/v1/zones` |
| `RecordRoutes` | `api/routes/RecordRoutes.hpp` | Handlers for `/api/v1/zones/{id}/records` |
| `VariableRoutes` | `api/routes/VariableRoutes.hpp` | Handlers for `/api/v1/variables` |
| `StagingRoutes` | `api/routes/StagingRoutes.hpp` | Handlers for `/api/v1/staging` |
| `AuthRoutes` | `api/routes/AuthRoutes.hpp` | Handlers for `/api/v1/auth` |
| `AuditRoutes` | `api/routes/AuditRoutes.hpp` | Handlers for `/api/v1/audit` |
| `HealthRoutes` | `api/routes/HealthRoutes.hpp` | Handler for `/api/v1/health` |
| `AuthMiddleware` | `api/AuthMiddleware.hpp` | JWT validation; injects `RequestContext` with identity |

**Request Context:**
Every authenticated request carries a `RequestContext` struct injected by `AuthMiddleware`:
```cpp
struct RequestContext {
    int64_t     user_id;
    std::string username;
    std::string role;       // "admin" | "operator" | "viewer"
    std::string auth_method; // "local" | "oidc" | "saml"
};
```

---

### 4.2 Core Engine

#### 4.2.1 Variable Engine

**Header:** `core/VariableEngine.hpp`

**Responsibilities:**
- Tokenize record value templates containing `{{var_name}}` placeholders
- Resolve variables using a two-level lookup: zone-scoped first, then global
- Detect and reject circular references
- Validate resolved types match the record type (e.g., `IPv4` for A records)

**Algorithm — `expand(value, zone_id, visited)`:**
```
1. Scan value for pattern \{\{([A-Za-z0-9_]+)\}\}
2. For each match token:
   a. If token in visited → throw CyclicVariableError
   b. Add token to visited
   c. Look up in zone-scoped variables WHERE zone_id = ?
   d. If not found, look up in global variables WHERE zone_id IS NULL
   e. If not found → throw UnresolvedVariableError
   f. Recursively call expand(resolved_value, zone_id, visited)
   g. Replace placeholder with expanded result
3. Return fully expanded string
```

**Limits:**
- Max recursion depth: 10 (configurable via `DNS_VAR_MAX_DEPTH` env var)
- Max variable name length: 64 characters

**Key Methods:**
```cpp
class VariableEngine {
public:
    std::string expand(const std::string& tmpl, int64_t zone_id) const;
    bool        validate(const std::string& tmpl, int64_t zone_id) const;
    std::vector<std::string> listDependencies(const std::string& tmpl) const;
};
```

#### 4.2.2 Diff/Preview Engine

**Header:** `core/DiffEngine.hpp`

**Responsibilities:**
- Fetch live records from the target provider via `IProvider::listRecords()`
- Fetch staged records from the DAL and expand all variables
- Compute a three-way diff: `{to_add, to_update, to_delete, drift}`
- Detect drift: records present on the provider but absent from the source of truth
- Return a structured `PreviewResult` for display in the GUI/TUI

**Key Types:**
```cpp
enum class DiffAction { Add, Update, Delete, Drift };

struct RecordDiff {
    DiffAction          action;
    std::string         name;
    std::string         type;
    std::string         provider_value;   // empty if action == Add
    std::string         source_value;     // empty if action == Drift
};

struct PreviewResult {
    int64_t                  zone_id;
    std::string              zone_name;
    std::vector<RecordDiff>  diffs;
    bool                     has_drift;
    std::chrono::system_clock::time_point generated_at;
};
```

#### 4.2.3 Deployment Engine

**Header:** `core/DeploymentEngine.hpp`

**Responsibilities:**
- Accept a `PreviewResult` and execute the diff against the provider
- Enforce per-zone serialization (one active push per zone at a time)
- Optionally purge drift records if `purge_drift` flag is set
- Trigger the GitOps mirror after a successful push
- Write an audit log entry for every record mutation

**Push Sequence:**
```
1. Acquire per-zone mutex (reject if already locked)
2. Re-run DiffEngine to get a fresh PreviewResult (guards against stale previews)
3. For each diff in PreviewResult:
   a. Add    → IProvider::createRecord()
   b. Update → IProvider::updateRecord()
   c. Delete → IProvider::deleteRecord()
   d. Drift  → IProvider::deleteRecord() if purge_drift == true
4. On any provider error → rollback attempted changes, release mutex, throw
5. Write audit log entries (bulk insert)
6. Trigger GitOpsMirror::commit(zone_id)
7. Release per-zone mutex
8. Clear staging entries for this zone
```

---

### 4.3 Provider Abstraction Layer

**Header:** `providers/IProvider.hpp`

All DNS provider integrations implement the `IProvider` pure abstract interface. This ensures the Core Engine is completely decoupled from provider-specific HTTP APIs.

```cpp
struct DnsRecord {
    std::string provider_record_id;  // opaque ID from provider
    std::string name;                // FQDN
    std::string type;                // A, AAAA, CNAME, MX, TXT, SRV, NS, PTR
    uint32_t    ttl;
    std::string value;               // fully expanded
    int         priority;            // MX/SRV only, 0 otherwise
};

enum class HealthStatus { Ok, Degraded, Unreachable };

struct PushResult {
    bool        success;
    std::string provider_record_id;  // assigned by provider on create
    std::string error_message;       // empty on success
};

class IProvider {
public:
    virtual ~IProvider() = default;

    virtual std::string              name()            const = 0;
    virtual HealthStatus             testConnectivity()      = 0;
    virtual std::vector<DnsRecord>   listRecords(const std::string& zone_name)  = 0;
    virtual PushResult               createRecord(const std::string& zone_name,
                                                  const DnsRecord& record)      = 0;
    virtual PushResult               updateRecord(const std::string& zone_name,
                                                  const DnsRecord& record)      = 0;
    virtual bool                     deleteRecord(const std::string& zone_name,
                                                  const std::string& provider_record_id) = 0;
};
```

**Concrete Implementations:**

| Class | Header | Notes |
|-------|--------|-------|
| `PowerDnsProvider` | `providers/PowerDnsProvider.hpp` | Uses PowerDNS REST API v1; supports zones and records endpoints |
| `CloudflareProvider` | `providers/CloudflareProvider.hpp` | Uses Cloudflare API v4; handles zone ID lookup by name |
| `DigitalOceanProvider` | `providers/DigitalOceanProvider.hpp` | Uses DigitalOcean API v2 `/domains` endpoint |

**Provider Factory:**
```cpp
// providers/ProviderFactory.hpp
class ProviderFactory {
public:
    static std::unique_ptr<IProvider> create(const std::string& type,
                                             const std::string& api_endpoint,
                                             const std::string& decrypted_token);
};
```

---

### 4.4 Data Access Layer

**Header prefix:** `dal/`

The DAL exposes typed repository classes. Each repository owns its SQL and uses `libpqxx` transactions. No raw SQL appears outside the DAL.

| Repository | Header | Manages |
|------------|--------|---------|
| `ProviderRepository` | `dal/ProviderRepository.hpp` | `providers` table; decrypts tokens on read |
| `ViewRepository` | `dal/ViewRepository.hpp` | `views` + `view_providers` join table |
| `ZoneRepository` | `dal/ZoneRepository.hpp` | `zones` table |
| `RecordRepository` | `dal/RecordRepository.hpp` | `records` table (raw templates) |
| `VariableRepository` | `dal/VariableRepository.hpp` | `variables` table |
| `StagingRepository` | `dal/StagingRepository.hpp` | `staging` table |
| `AuditRepository` | `dal/AuditRepository.hpp` | `audit_log` table (insert-only) |
| `UserRepository` | `dal/UserRepository.hpp` | `users` + `groups` + `group_members` |
| `SessionRepository` | `dal/SessionRepository.hpp` | `sessions` table |

**Connection Pool:**
- `dal/ConnectionPool.hpp` — fixed-size pool of `pqxx::connection` objects
- Pool size configurable via `DNS_DB_POOL_SIZE` (default: 10)
- Connections are checked out with RAII guard `ConnectionGuard`

---

### 4.5 GitOps Mirror Subsystem

**Header:** `gitops/GitOpsMirror.hpp`

**Responsibilities:**
- Maintain a local bare-clone of the configured Git remote
- After each successful push, generate fully-expanded JSON zone snapshots
- Stage, commit, and push changes to the remote using `libgit2`

**Repo Layout:**
```
/var/dns-orchestrator/repo/
  {view_name}/
    {provider_name}/
      {zone_name}.json
```

**Zone Snapshot Format (`{zone_name}.json`):**
```json
{
  "zone": "example.com",
  "view": "external",
  "provider": "cloudflare",
  "generated_at": "2026-02-26T21:00:00Z",
  "generated_by": "alice",
  "records": [
    {
      "name": "www.example.com.",
      "type": "A",
      "ttl": 300,
      "value": "203.0.113.10"
    }
  ]
}
```

**Key Methods:**
```cpp
class GitOpsMirror {
public:
    void initialize(const std::string& remote_url, const std::string& local_path);
    void commit(int64_t zone_id, const std::string& actor_identity);
    void pull();   // called at startup to sync local clone
private:
    void writeZoneSnapshot(int64_t zone_id);
    void gitAddCommitPush(const std::string& message);
};
```

**Conflict Strategy:** The mirror is append/overwrite only. The Git repo is never the source of truth, so merge conflicts are resolved by force-pushing the current DB state. A conflict is logged as a warning in the audit log.

---

### 4.6 Security Subsystem

**Header prefix:** `security/`

#### 4.6.1 Credential Encryption

**Header:** `security/CryptoService.hpp`

- Algorithm: AES-256-GCM (via OpenSSL 3.x EVP API)
- Master key: loaded from `DNS_MASTER_KEY` environment variable (32-byte hex string)
- Each provider token is encrypted with a unique 12-byte random IV stored alongside the ciphertext
- Storage format: `base64(iv) + ":" + base64(ciphertext + tag)`

```cpp
class CryptoService {
public:
    std::string encrypt(const std::string& plaintext) const;
    std::string decrypt(const std::string& ciphertext) const;
};
```

#### 4.6.2 Authentication

**Header:** `security/AuthService.hpp`

The system supports three authentication methods simultaneously. All methods produce a JWT session token upon success.

**Local Authentication (User/Group/Role):**
- Passwords hashed with Argon2id (via OpenSSL or `libsodium`)
- Users belong to one or more groups
- Groups are assigned roles: `admin`, `operator`, `viewer`
- Role resolution: highest-privilege role across all groups wins

**OIDC Authentication:**
- Implements Authorization Code Flow with PKCE
- Validates ID token signature against provider JWKS endpoint
- Maps OIDC `sub` claim to a local user record (auto-provisioned on first login if `DNS_OIDC_AUTO_PROVISION=true`)
- Configurable claim-to-role mapping via `DNS_OIDC_ROLE_CLAIM`

**SAML 2.0 Authentication:**
- SP-initiated SSO via HTTP POST binding
- Validates assertion signature against IdP metadata
- Maps SAML attribute to role via configurable attribute name (`DNS_SAML_ROLE_ATTR`)
- Auto-provisions users on first login if `DNS_SAML_AUTO_PROVISION=true`

**Session Tokens:**
- JWT (HS256), signed with `DNS_JWT_SECRET`
- Payload: `{ sub, username, role, auth_method, iat, exp }`
- Default expiry: 8 hours (configurable via `DNS_JWT_TTL_SECONDS`)
- Token hash stored in `sessions` table for revocation support

**RBAC Matrix:**

| Action | viewer | operator | admin |
|--------|--------|----------|-------|
| Read records/zones/views | ✓ | ✓ | ✓ |
| Create/update/delete records | ✗ | ✓ | ✓ |
| Stage changes | ✗ | ✓ | ✓ |
| Preview diff | ✓ | ✓ | ✓ |
| Push deployment | ✗ | ✓ | ✓ |
| Manage providers | ✗ | ✗ | ✓ |
| Manage variables | ✗ | ✓ | ✓ |
| Manage users/groups | ✗ | ✗ | ✓ |
| View audit log | ✓ | ✓ | ✓ |

---

### 4.7 TUI Layer

**Header prefix:** `tui/`
**Framework:** FTXUI

**Screen Hierarchy:**
```
TuiApp
├── LoginScreen          ← local/OIDC device-flow login
├── MainScreen
│   ├── ViewSwitcher     ← keystroke: Tab cycles through views
│   ├── ZoneListPane     ← left panel: zones in current view
│   ├── RecordTablePane  ← right panel: records for selected zone
│   │   ├── RecordEditModal   ← inline edit with Vim bindings (hjkl, i, Esc)
│   │   └── VariablePickerModal ← autocomplete for {{var}} insertion
│   ├── StagingPane      ← bottom panel: pending staged changes
│   ├── PreviewScreen    ← full-screen diff view before push
│   └── StatusBar        ← current view, zone, user, last sync time
└── AuditLogScreen       ← scrollable audit log viewer
```

**Key Bindings:**

| Key | Action |
|-----|--------|
| `Tab` | Cycle between views (Internal / External / ...) |
| `j` / `k` | Navigate records up/down |
| `i` | Enter edit mode on selected record |
| `Esc` | Cancel edit / close modal |
| `p` | Open preview diff for current zone |
| `P` | Push staged changes for current zone |
| `s` | Stage current edit |
| `?` | Show help overlay |
| `q` | Quit |

**TUI ↔ API Communication:**
The TUI communicates with the same REST API as the Web GUI. It does not have direct DB access. This ensures a single code path for all mutations.

---

### 4.8 Thread Pool and Concurrency Model

**Header:** `core/ThreadPool.hpp`

**Design:**
- Fixed-size pool of `std::jthread` workers (size: `DNS_THREAD_POOL_SIZE`, default: `std::thread::hardware_concurrency()`)
- Work queue: `std::queue<std::packaged_task<void()>>` protected by `std::mutex` + `std::condition_variable`
- Returns `std::future<T>` for async result retrieval

**Concurrency Rules:**

| Operation | Concurrency Policy |
|-----------|-------------------|
| Preview (diff) | Fully parallel; multiple zones can be previewed simultaneously |
| Push (deploy) | Serialized per zone via `std::unordered_map<int64_t, std::mutex>` (zone_id → mutex) |
| GitOps commit | Serialized globally via a single `std::mutex` on `GitOpsMirror` |
| DB reads | Concurrent via connection pool |
| DB writes | Serialized per-transaction by `libpqxx` |

---

## 5. PostgreSQL Schema

### 5.1 Enumerations

```sql
CREATE TYPE provider_type   AS ENUM ('powerdns', 'cloudflare', 'digitalocean');
CREATE TYPE variable_type   AS ENUM ('ipv4', 'ipv6', 'target', 'string');
CREATE TYPE variable_scope  AS ENUM ('global', 'zone');
CREATE TYPE staging_op      AS ENUM ('create', 'update', 'delete');
CREATE TYPE user_role       AS ENUM ('admin', 'operator', 'viewer');
CREATE TYPE auth_method     AS ENUM ('local', 'oidc', 'saml');
```

### 5.2 Tables

```sql
-- Provider registry
CREATE TABLE providers (
    id              BIGSERIAL PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    type            provider_type NOT NULL,
    api_endpoint    TEXT NOT NULL,
    encrypted_token TEXT NOT NULL,          -- AES-256-GCM encrypted
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
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL,               -- e.g. "example.com"
    view_id    BIGINT NOT NULL REFERENCES views(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (name, view_id)
);

-- Variable registry
CREATE TABLE variables (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL,
    value      TEXT NOT NULL,
    type       variable_type NOT NULL,
    scope      variable_scope NOT NULL DEFAULT 'global',
    zone_id    BIGINT REFERENCES zones(id) ON DELETE CASCADE,  -- NULL = global
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (name, zone_id),                 -- zone_id NULL treated as global namespace
    CHECK (scope = 'global' AND zone_id IS NULL
        OR scope = 'zone'   AND zone_id IS NOT NULL)
);

-- DNS records (stores raw templates with {{var}} placeholders)
CREATE TABLE records (
    id             BIGSERIAL PRIMARY KEY,
    zone_id        BIGINT NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
    name           TEXT NOT NULL,           -- relative or FQDN
    type           TEXT NOT NULL,           -- A, AAAA, CNAME, MX, TXT, SRV, NS, PTR
    ttl            INTEGER NOT NULL DEFAULT 300,
    value_template TEXT NOT NULL,           -- may contain {{var_name}} tokens
    priority       INTEGER NOT NULL DEFAULT 0,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Staging table for pending changes
CREATE TABLE staging (
    id             BIGSERIAL PRIMARY KEY,
    record_id      BIGINT REFERENCES records(id) ON DELETE SET NULL,
    zone_id        BIGINT NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
    operation      staging_op NOT NULL,
    new_value      TEXT,                    -- NULL for delete operations
    submitted_by   BIGINT NOT NULL REFERENCES users(id),
    submitted_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Audit log (append-only; no updates or deletes)
CREATE TABLE audit_log (
    id            BIGSERIAL PRIMARY KEY,
    entity_type   TEXT NOT NULL,            -- 'record', 'variable', 'provider', etc.
    entity_id     BIGINT,
    operation     TEXT NOT NULL,            -- 'create', 'update', 'delete', 'push', 'login'
    old_value     JSONB,
    new_value     JSONB,
    variable_used TEXT,                     -- variable name if expansion was involved
    identity      TEXT NOT NULL,            -- username or system
    auth_method   auth_method,
    ip_address    INET,
    timestamp     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Users
CREATE TABLE users (
    id            BIGSERIAL PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    email         TEXT UNIQUE,
    password_hash TEXT,                     -- NULL for SSO-only users
    oidc_sub      TEXT UNIQUE,              -- NULL for local/SAML users
    saml_name_id  TEXT UNIQUE,              -- NULL for local/OIDC users
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

-- Active sessions
CREATE TABLE sessions (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,       -- SHA-256 of JWT
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked     BOOLEAN NOT NULL DEFAULT FALSE
);
```

### 5.3 Indexes

```sql
CREATE INDEX idx_records_zone_id       ON records(zone_id);
CREATE INDEX idx_staging_zone_id       ON staging(zone_id);
CREATE INDEX idx_variables_zone_id     ON variables(zone_id);
CREATE INDEX idx_audit_log_timestamp   ON audit_log(timestamp DESC);
CREATE INDEX idx_audit_log_entity      ON audit_log(entity_type, entity_id);
CREATE INDEX idx_sessions_user_id      ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at   ON sessions(expires_at);
```

### 5.4 Migrations

Migration files live in `scripts/db/` and are numbered sequentially:
```
scripts/db/
  001_initial_schema.sql
  002_add_indexes.sql
  ...
```

---

## 6. REST API Contract

**Base URL:** `/api/v1`
**Content-Type:** `application/json`
**Authentication:** `Authorization: Bearer <jwt>` on all endpoints except `/auth/*` and `/health`

### 6.1 Authentication

| Method | Path | Auth Required | Description |
|--------|------|---------------|-------------|
| `POST` | `/auth/local/login` | No | Username + password login; returns JWT |
| `POST` | `/auth/local/logout` | Yes | Revokes current session token |
| `GET`  | `/auth/oidc/authorize` | No | Redirects to OIDC provider |
| `GET`  | `/auth/oidc/callback` | No | OIDC callback; exchanges code for JWT |
| `GET`  | `/auth/saml/login` | No | Initiates SAML SP-initiated SSO |
| `POST` | `/auth/saml/acs` | No | SAML Assertion Consumer Service endpoint |
| `GET`  | `/auth/me` | Yes | Returns current user identity and role |

### 6.2 Providers

| Method | Path | Role Required | Description |
|--------|------|---------------|-------------|
| `GET`    | `/providers` | viewer | List all providers |
| `POST`   | `/providers` | admin | Create a provider |
| `GET`    | `/providers/{id}` | viewer | Get provider by ID |
| `PUT`    | `/providers/{id}` | admin | Update provider |
| `DELETE` | `/providers/{id}` | admin | Delete provider |
| `GET`    | `/providers/{id}/health` | operator | Test provider connectivity |

### 6.3 Views

| Method | Path | Role Required | Description |
|--------|------|---------------|-------------|
| `GET`    | `/views` | viewer | List all views |
| `POST`   | `/views` | admin | Create a view |
| `GET`    | `/views/{id}` | viewer | Get view by ID |
| `PUT`    | `/views/{id}` | admin | Update view |
| `DELETE` | `/views/{id}` | admin | Delete view |
| `POST`   | `/views/{id}/providers/{pid}` | admin | Attach provider to view |
| `DELETE` | `/views/{id}/providers/{pid}` | admin | Detach provider from view |

### 6.4 Zones

| Method | Path | Role Required | Description |
|--------|------|---------------|-------------|
| `GET`    | `/zones` | viewer | List all zones (filterable by `?view_id=`) |
| `POST`   | `/zones` | admin | Create a zone |
| `GET`    | `/zones/{id}` | viewer | Get zone by ID |
| `PUT`    | `/zones/{id}` | admin | Update zone |
| `DELETE` | `/zones/{id}` | admin | Delete zone |

### 6.5 Records

| Method | Path | Role Required | Description |
|--------|------|---------------|-------------|
| `GET`    | `/zones/{id}/records` | viewer | List all records for a zone |
| `POST`   | `/zones/{id}/records` | operator | Create a record |
| `GET`    | `/zones/{id}/records/{rid}` | viewer | Get record by ID |
| `PUT`    | `/zones/{id}/records/{rid}` | operator | Update a record |
| `DELETE` | `/zones/{id}/records/{rid}` | operator | Delete a record |

### 6.6 Variables

| Method | Path | Role Required | Description |
|--------|------|---------------|-------------|
| `GET`    | `/variables` | viewer | List variables (filterable by `?scope=global` or `?zone_id=`) |
| `POST`   | `/variables` | operator | Create a variable |
| `GET`    | `/variables/{id}` | viewer | Get variable by ID |
| `PUT`    | `/variables/{id}` | operator | Update a variable |
| `DELETE` | `/variables/{id}` | operator | Delete a variable |

### 6.7 Staging and Deployment

| Method | Path | Role Required | Description |
|--------|------|---------------|-------------|
| `GET`    | `/staging` | viewer | List all staged changes (filterable by `?zone_id=`) |
| `DELETE` | `/staging/{id}` | operator | Discard a staged change |
| `POST`   | `/staging/preview/{zone_id}` | viewer | Run diff preview for a zone; returns `PreviewResult` |
| `POST`   | `/staging/push/{zone_id}` | operator | Execute deployment for a zone |

**Preview Response Shape:**
```json
{
  "zone_id": 42,
  "zone_name": "example.com",
  "generated_at": "2026-02-26T21:00:00Z",
  "has_drift": false,
  "diffs": [
    {
      "action": "update",
      "name": "www.example.com.",
      "type": "A",
      "provider_value": "203.0.113.9",
      "source_value": "203.0.113.10"
    }
  ]
}
```

### 6.8 Users and Groups

| Method | Path | Role Required | Description |
|--------|------|---------------|-------------|
| `GET`    | `/users` | admin | List all users |
| `POST`   | `/users` | admin | Create a local user |
| `GET`    | `/users/{id}` | admin | Get user by ID |
| `PUT`    | `/users/{id}` | admin | Update user |
| `DELETE` | `/users/{id}` | admin | Deactivate user |
| `GET`    | `/groups` | admin | List all groups |
| `POST`   | `/groups` | admin | Create a group |
| `PUT`    | `/groups/{id}` | admin | Update group |
| `DELETE` | `/groups/{id}` | admin | Delete group |
| `POST`   | `/groups/{id}/members/{uid}` | admin | Add user to group |
| `DELETE` | `/groups/{id}/members/{uid}` | admin | Remove user from group |

### 6.9 Audit Log

| Method | Path | Role Required | Description |
|--------|------|---------------|-------------|
| `GET` | `/audit` | viewer | Query audit log (filterable by `?entity_type=`, `?identity=`, `?from=`, `?to=`) |

### 6.10 Health

| Method | Path | Auth Required | Description |
|--------|------|---------------|-------------|
| `GET` | `/health` | No | Returns `{"status":"ok"}` or `{"status":"degraded","detail":"..."}` |

---

## 7. Data Flow Diagrams

### 7.1 Staging → Preview → Deploy Pipeline

```
User
 │
 ├─[1] PUT /zones/{id}/records/{rid}  (operator)
 │      └─ RecordRepository::update() → writes value_template to records table
 │         └─ StagingRepository::create() → writes to staging table
 │
 ├─[2] POST /staging/preview/{zone_id}  (viewer)
 │      └─ DiffEngine::preview(zone_id)
 │           ├─ DAL: fetch staged records for zone
 │           ├─ VariableEngine::expand() for each staged record
 │           ├─ IProvider::listRecords(zone_name) → live state from provider
 │           └─ Compute diff → return PreviewResult
 │
 └─[3] POST /staging/push/{zone_id}  (operator)
        └─ DeploymentEngine::push(zone_id, purge_drift)
             ├─ Acquire per-zone mutex
             ├─ Re-run DiffEngine::preview() (freshness guard)
             ├─ For each diff: IProvider::createRecord / updateRecord / deleteRecord
             ├─ AuditRepository::bulkInsert(audit entries)
             ├─ GitOpsMirror::commit(zone_id, actor)
             ├─ StagingRepository::clearZone(zone_id)
             └─ Release per-zone mutex
```

### 7.2 Variable Expansion Flow

```
record.value_template = "{{LB_VIP}}"
         │
         ▼
VariableEngine::expand("{{LB_VIP}}", zone_id=42, visited={})
         │
         ├─ Tokenize → ["LB_VIP"]
         ├─ visited.insert("LB_VIP")
         ├─ VariableRepository::findByName("LB_VIP", zone_id=42)
         │     → found: value="{{DATACENTER_VIP}}", scope=zone
         │
         └─ Recurse: expand("{{DATACENTER_VIP}}", zone_id=42, visited={"LB_VIP"})
                  ├─ Tokenize → ["DATACENTER_VIP"]
                  ├─ visited.insert("DATACENTER_VIP")
                  ├─ VariableRepository::findByName("DATACENTER_VIP", zone_id=42)
                  │     → not found in zone scope
                  ├─ VariableRepository::findByName("DATACENTER_VIP", zone_id=NULL)
                  │     → found: value="203.0.113.10", scope=global
                  └─ No more tokens → return "203.0.113.10"
         │
         └─ Final result: "203.0.113.10"
```

### 7.3 GitOps Mirror Flow

```
DeploymentEngine::push() completes successfully
         │
         ▼
GitOpsMirror::commit(zone_id=42, actor="alice")
         │
         ├─ writeZoneSnapshot(zone_id=42)
         │     ├─ ZoneRepository::get(42) → zone_name="example.com", view="external", provider="cloudflare"
         │     ├─ RecordRepository::listByZone(42) → raw templates
         │     ├─ VariableEngine::expand() for each record
         │     └─ Write JSON to /var/dns-orchestrator/repo/external/cloudflare/example.com.json
         │
         └─ gitAddCommitPush("Update example.com by alice via API")
               ├─ libgit2: git_index_add_all()
               ├─ libgit2: git_commit_create()
               └─ libgit2: git_remote_push()
```

### 7.4 Authentication Flow

```
Local Login:
  POST /auth/local/login {"username":"alice","password":"..."}
    └─ AuthService::authenticateLocal()
         ├─ UserRepository::findByUsername("alice")
         ├─ Argon2id verify(password, stored_hash)
         ├─ Resolve role: GroupRepository::getHighestRole(user_id)
         ├─ Generate JWT {sub, username, role, auth_method="local", exp}
         ├─ SessionRepository::create(user_id, SHA256(jwt), expires_at)
         └─ Return {"token": "<jwt>"}

OIDC Login:
  GET /auth/oidc/authorize
    └─ Redirect to IdP with client_id, redirect_uri, code_challenge (PKCE)

  GET /auth/oidc/callback?code=...&state=...
    └─ AuthService::authenticateOidc(code)
         ├─ Exchange code for id_token at IdP token endpoint
         ├─ Validate id_token signature against JWKS
         ├─ Extract sub, email, role_claim
         ├─ UserRepository::findOrCreateByOidcSub(sub)
         ├─ Generate JWT and create session
         └─ Return {"token": "<jwt>"}

Every Authenticated Request:
  Authorization: Bearer <jwt>
    └─ AuthMiddleware::validate(jwt)
         ├─ Verify JWT signature (HS256, DNS_JWT_SECRET)
         ├─ Check exp not exceeded
         ├─ SessionRepository::isRevoked(SHA256(jwt))
         └─ Inject RequestContext into handler
```

---

## 8. Configuration and Environment Variables

All configuration is provided via environment variables. No config files are required at runtime (though a `.env` file may be used in development).

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DNS_DB_URL` | Yes | — | PostgreSQL connection string (`postgresql://user:pass@host:5432/dbname`) |
| `DNS_DB_POOL_SIZE` | No | `10` | Number of DB connections in the pool |
| `DNS_MASTER_KEY` | Yes | — | 32-byte hex string for AES-256-GCM credential encryption |
| `DNS_JWT_SECRET` | Yes | — | Secret for JWT HS256 signing |
| `DNS_JWT_TTL_SECONDS` | No | `28800` | JWT expiry in seconds (default 8 hours) |
| `DNS_HTTP_PORT` | No | `8080` | Port for the Restbed HTTP server |
| `DNS_HTTP_THREADS` | No | `4` | Restbed worker thread count |
| `DNS_THREAD_POOL_SIZE` | No | `hw_concurrency` | Core engine thread pool size |
| `DNS_VAR_MAX_DEPTH` | No | `10` | Maximum variable expansion recursion depth |
| `DNS_GIT_REMOTE_URL` | No | — | Git remote URL for GitOps mirror (disabled if unset) |
| `DNS_GIT_LOCAL_PATH` | No | `/var/dns-orchestrator/repo` | Local path for Git mirror clone |
| `DNS_GIT_SSH_KEY_PATH` | No | — | Path to SSH private key for Git push auth |
| `DNS_OIDC_ISSUER` | No | — | OIDC issuer URL (enables OIDC if set) |
| `DNS_OIDC_CLIENT_ID` | No | — | OIDC client ID |
| `DNS_OIDC_CLIENT_SECRET` | No | — | OIDC client secret |
| `DNS_OIDC_REDIRECT_URI` | No | — | OIDC redirect URI |
| `DNS_OIDC_ROLE_CLAIM` | No | `dns_role` | JWT claim name to map to RBAC role |
| `DNS_OIDC_AUTO_PROVISION` | No | `false` | Auto-create users on first OIDC login |
| `DNS_SAML_IDP_METADATA_URL` | No | — | SAML IdP metadata URL (enables SAML if set) |
| `DNS_SAML_SP_ENTITY_ID` | No | — | SAML SP entity ID |
| `DNS_SAML_ACS_URL` | No | — | SAML Assertion Consumer Service URL |
| `DNS_SAML_ROLE_ATTR` | No | `dns_role` | SAML attribute name to map to RBAC role |
| `DNS_SAML_AUTO_PROVISION` | No | `false` | Auto-create users on first SAML login |
| `DNS_AUDIT_STDOUT` | No | `false` | Mirror audit log entries to stdout (for Docker log collection) |
| `DNS_LOG_LEVEL` | No | `info` | Log level: `debug`, `info`, `warn`, `error` |

---

## 9. Error Taxonomy and Handling Strategy

### 9.1 Error Hierarchy

All application errors derive from a common base:

```cpp
// common/Errors.hpp
struct AppError : public std::runtime_error {
    int         http_status;
    std::string error_code;   // machine-readable slug
    explicit AppError(int status, std::string code, std::string msg);
};

// Derived types
struct ValidationError      : AppError { /* 400 */ };
struct AuthenticationError  : AppError { /* 401 */ };
struct AuthorizationError   : AppError { /* 403 */ };
struct NotFoundError        : AppError { /* 404 */ };
struct ConflictError        : AppError { /* 409 */ };
struct ProviderError        : AppError { /* 502 */ };
struct UnresolvedVariableError : AppError { /* 422 */ };
struct CyclicVariableError  : AppError { /* 422 */ };
struct DeploymentLockedError : AppError { /* 409 */ };
struct GitMirrorError       : AppError { /* 500, non-fatal: logged, push still succeeds */ };
```

### 9.2 Error Response Shape

All API errors return a consistent JSON body:

```json
{
  "error": {
    "code": "unresolved_variable",
    "message": "Variable 'LB_VIP' is not defined in zone scope or global scope",
    "details": {
      "variable": "LB_VIP",
      "record_id": 99
    }
  }
}
```

### 9.3 Error Handling Rules

| Scenario | Behavior |
|----------|----------|
| Variable unresolved at preview | Fail preview; return 422 with variable name |
| Variable cycle detected | Fail preview; return 422 with cycle path |
| Provider API unreachable at preview | Fail preview; return 502 |
| Provider API error during push | Rollback attempted changes; return 502; log to audit |
| Zone already being pushed | Return 409 `deployment_locked` |
| Git mirror push fails | Log warning to audit; push is still marked successful |
| DB connection unavailable | Return 503; log to stderr |
| JWT expired | Return 401 `token_expired` |
| JWT revoked | Return 401 `token_revoked` |

---

## 10. Directory and File Structure

```
dns-orchestrator/
├── CMakeLists.txt
├── SPEC.md
├── ARCHITECTURE.md
├── README.md
├── .gitmodules
│
├── include/                        # Public headers (interface declarations)
│   ├── common/
│   │   ├── Errors.hpp              # AppError hierarchy
│   │   ├── Logger.hpp              # Structured logging interface
│   │   ├── Config.hpp              # Environment variable loader
│   │   └── Types.hpp               # Shared value types (DnsRecord, etc.)
│   ├── api/
│   │   ├── ApiServer.hpp
│   │   ├── AuthMiddleware.hpp
│   │   └── routes/
│   │       ├── AuthRoutes.hpp
│   │       ├── ProviderRoutes.hpp
│   │       ├── ViewRoutes.hpp
│   │       ├── ZoneRoutes.hpp
│   │       ├── RecordRoutes.hpp
│   │       ├── VariableRoutes.hpp
│   │       ├── StagingRoutes.hpp
│   │       ├── AuditRoutes.hpp
│   │       └── HealthRoutes.hpp
│   ├── core/
│   │   ├── VariableEngine.hpp
│   │   ├── DiffEngine.hpp
│   │   ├── DeploymentEngine.hpp
│   │   └── ThreadPool.hpp
│   ├── providers/
│   │   ├── IProvider.hpp           # Pure abstract interface
│   │   ├── ProviderFactory.hpp
│   │   ├── PowerDnsProvider.hpp
│   │   ├── CloudflareProvider.hpp
│   │   └── DigitalOceanProvider.hpp
│   ├── dal/
│   │   ├── ConnectionPool.hpp
│   │   ├── ProviderRepository.hpp
│   │   ├── ViewRepository.hpp
│   │   ├── ZoneRepository.hpp
│   │   ├── RecordRepository.hpp
│   │   ├── VariableRepository.hpp
│   │   ├── StagingRepository.hpp
│   │   ├── AuditRepository.hpp
│   │   ├── UserRepository.hpp
│   │   └── SessionRepository.hpp
│   ├── gitops/
│   │   └── GitOpsMirror.hpp
│   ├── security/
│   │   ├── CryptoService.hpp
│   │   └── AuthService.hpp
│   └── tui/
│       ├── TuiApp.hpp
│       ├── screens/
│       │   ├── LoginScreen.hpp
│       │   ├── MainScreen.hpp
│       │   ├── PreviewScreen.hpp
│       │   └── AuditLogScreen.hpp
│       └── components/
│           ├── ViewSwitcher.hpp
│           ├── ZoneListPane.hpp
│           ├── RecordTablePane.hpp
│           ├── StagingPane.hpp
│           ├── RecordEditModal.hpp
│           ├── VariablePickerModal.hpp
│           └── StatusBar.hpp
│
├── src/                            # Implementation files
│   ├── main.cpp
│   ├── common/
│   │   ├── Logger.cpp
│   │   └── Config.cpp
│   ├── api/
│   │   ├── ApiServer.cpp
│   │   ├── AuthMiddleware.cpp
│   │   └── routes/
│   │       └── *.cpp
│   ├── core/
│   │   ├── VariableEngine.cpp
│   │   ├── DiffEngine.cpp
│   │   ├── DeploymentEngine.cpp
│   │   └── ThreadPool.cpp
│   ├── providers/
│   │   ├── ProviderFactory.cpp
│   │   ├── PowerDnsProvider.cpp
│   │   ├── CloudflareProvider.cpp
│   │   └── DigitalOceanProvider.cpp
│   ├── dal/
│   │   ├── ConnectionPool.cpp
│   │   └── *Repository.cpp
│   ├── gitops/
│   │   └── GitOpsMirror.cpp
│   ├── security/
│   │   ├── CryptoService.cpp
│   │   └── AuthService.cpp
│   └── tui/
│       ├── TuiApp.cpp
│       ├── screens/
│       │   └── *.cpp
│       └── components/
│           └── *.cpp
│
├── tests/
│   ├── unit/
│   │   ├── test_variable_engine.cpp
│   │   ├── test_diff_engine.cpp
│   │   ├── test_crypto_service.cpp
│   │   └── test_provider_factory.cpp
│   └── integration/
│       ├── test_deployment_pipeline.cpp
│       └── test_gitops_mirror.cpp
│
├── scripts/
│   ├── db/
│   │   ├── 001_initial_schema.sql
│   │   └── 002_add_indexes.sql
│   └── docker/
│       └── entrypoint.sh
│
├── docs/
│   └── api/                        # OpenAPI spec (future)
│
└── plans/                          # Architecture and planning documents
```

---

## 11. Dockerfile and Deployment Model

### 11.1 Multi-Stage Dockerfile

```dockerfile
# ── Stage 1: Build ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake ninja-build gcc-12 g++-12 \
    libpqxx-dev libssl-dev libgit2-dev \
    librestbed-dev nlohmann-json3-dev \
    libftxui-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

RUN cmake -B build -G Ninja \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_CXX_COMPILER=g++-12 \
    && cmake --build build --parallel

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 libssl3 libgit2-1.5 librestbed0 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --no-create-home dns-orchestrator

COPY --from=builder /build/build/dns-orchestrator /usr/local/bin/dns-orchestrator
COPY scripts/docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER dns-orchestrator
EXPOSE 8080

ENTRYPOINT ["/entrypoint.sh"]
CMD ["dns-orchestrator"]
```

### 11.2 entrypoint.sh

```bash
#!/bin/sh
set -e

# Run DB migrations before starting the server
dns-orchestrator --migrate

exec "$@"
```

### 11.3 Docker Compose (Development)

```yaml
services:
  db:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: dns_orchestrator
      POSTGRES_USER: dns
      POSTGRES_PASSWORD: dns
    volumes:
      - pgdata:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  app:
    build: .
    depends_on:
      - db
    environment:
      DNS_DB_URL: postgresql://dns:dns@db:5432/dns_orchestrator
      DNS_MASTER_KEY: ${DNS_MASTER_KEY}
      DNS_JWT_SECRET: ${DNS_JWT_SECRET}
      DNS_HTTP_PORT: "8080"
      DNS_AUDIT_STDOUT: "true"
    ports:
      - "8080:8080"
    volumes:
      - gitrepo:/var/dns-orchestrator/repo

volumes:
  pgdata:
  gitrepo:
```

### 11.4 Startup Sequence

```
1. Load and validate all required environment variables (fail fast if missing)
2. Initialize CryptoService with DNS_MASTER_KEY
3. Initialize ConnectionPool (DNS_DB_URL, DNS_DB_POOL_SIZE)
4. Run pending DB migrations (scripts/db/*.sql in order)
5. Initialize GitOpsMirror (if DNS_GIT_REMOTE_URL is set): git clone or git pull
6. Initialize ThreadPool (DNS_THREAD_POOL_SIZE workers)
7. Initialize ProviderFactory
8. Register all API routes on ApiServer
9. Start Restbed HTTP server on DNS_HTTP_PORT
10. Log "dns-orchestrator ready" to stdout
```