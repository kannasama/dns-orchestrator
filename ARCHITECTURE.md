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
  - 4.9 [Maintenance Scheduler](#49-maintenance-scheduler)
5. [PostgreSQL Schema](#5-postgresql-schema)
6. [REST API Contract](#6-rest-api-contract)
7. [Data Flow Diagrams](#7-data-flow-diagrams)
  - 7.1 [Edit → Preview → Deploy → Rollback Pipeline](#71-edit--preview--deploy--rollback-pipeline)
  - 7.2 [Variable Expansion Flow](#72-variable-expansion-flow)
  - 7.3 [GitOps Mirror Flow](#73-gitops-mirror-flow)
  - 7.4 [Authentication Flow](#74-authentication-flow)
8. [Configuration and Environment Variables](#8-configuration-and-environment-variables)
9. [Error Taxonomy and Handling Strategy](#9-error-taxonomy-and-handling-strategy)
10. [Directory and File Structure](#10-directory-and-file-structure)
11. [Dockerfile and Deployment Model](#11-dockerfile-and-deployment-model)
12. [Security Hardening Reference](#12-security-hardening-reference)
  - 12.1 [Deployment Security Requirements](#121-deployment-security-requirements)
  - 12.2 [PostgreSQL Least-Privilege Roles](#122-postgresql-least-privilege-roles)
  - 12.3 [Secret Management](#123-secret-management)
  - 12.4 [Rate Limiting (Reverse Proxy)](#124-rate-limiting-reverse-proxy)
  - 12.5 [Git Remote Security](#125-git-remote-security)

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
- Serialize responses as JSON (`nlohmann/json`, 2-space indent)
- Return structured error responses (see §9)

**Key Classes:**

| Class | Header | Responsibility |
|-------|--------|----------------|
| `ApiServer` | `api/ApiServer.hpp` | Owns the `restbed::Service` instance; registers all routes at startup |
| `ProviderRoutes` | `api/routes/ProviderRoutes.hpp` | Handlers for `/api/v1/providers` |
| `ViewRoutes` | `api/routes/ViewRoutes.hpp` | Handlers for `/api/v1/views` |
| `ZoneRoutes` | `api/routes/ZoneRoutes.hpp` | Handlers for `/api/v1/zones` |
| `RecordRoutes` | `api/routes/RecordRoutes.hpp` | Handlers for `/api/v1/zones/{id}/records` and preview/push |
| `VariableRoutes` | `api/routes/VariableRoutes.hpp` | Handlers for `/api/v1/variables` |
| `DeploymentRoutes` | `api/routes/DeploymentRoutes.hpp` | Handlers for `/api/v1/zones/{id}/deployments` and rollback |
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
  std::string auth_method; // "local" | "oidc" | "saml" | "api_key"
};
```

**AuthMiddleware Dual-Mode Validation:**
`AuthMiddleware` accepts two mutually exclusive credential schemes on every request:

1. **JWT Bearer** (`Authorization: Bearer <jwt>`) — used by the Web GUI and any client that completed an interactive login flow.
2. **API Key** (`X-API-Key: <raw_key>`) — used by the TUI and any automated/scripted client.

```
Incoming request
  ├─ Has "Authorization: Bearer <token>"?
  │     ├─ Verify JWT signature (HS256, DNS_JWT_SECRET)
  │     ├─ Check exp not exceeded (JWT exp claim)
  │     ├─ SessionRepository::exists(SHA256(jwt))
  │     │     └─ If row absent → session was revoked or expired and deleted → 401 token_revoked
  │     ├─ Check sessions.expires_at > NOW() (sliding window)
  │     │     └─ If expired → SessionRepository::deleteByHash(SHA256(jwt)) → 401 token_expired
  │     ├─ Check sessions.absolute_expires_at > NOW() (hard ceiling)
  │     │     └─ If exceeded → SessionRepository::deleteByHash(SHA256(jwt)) → 401 token_expired
  │     ├─ SessionRepository::touch(SHA256(jwt), DNS_JWT_TTL_SECONDS, DNS_SESSION_ABSOLUTE_TTL_SECONDS)
  │     │     -- extends expires_at by DNS_JWT_TTL_SECONDS, clamped to absolute_expires_at
  │     └─ Inject RequestContext {auth_method="local"|"oidc"|"saml"}
  └─ Has "X-API-Key: <key>"?
        ├─ SHA-256 hash the raw key
        ├─ ApiKeyRepository::findByHash(hash)
        │     └─ If not found → 401 invalid_api_key
        ├─ Check revoked=false
        │     └─ If revoked → 401 api_key_revoked
        ├─ Check expires_at IS NULL OR expires_at > NOW()
        │     └─ If expired → ApiKeyRepository::scheduleDelete(id, DNS_API_KEY_CLEANUP_GRACE_SECONDS)
        │                   → 401 api_key_expired
        ├─ UserRepository::findById(user_id) → username + resolve role
        └─ Inject RequestContext {auth_method="api_key"}
```

If neither header is present, or validation fails, `AuthMiddleware` returns `401 AuthenticationError`.

**Session lifecycle events (immediate cleanup):**

| Event | Action |
|-------|--------|
| Logout (`POST /auth/local/logout`) | `SessionRepository::deleteByHash(token_hash)` — hard DELETE; audit log records the logout |
| Revocation (admin action) | `SessionRepository::deleteByHash(token_hash)` — hard DELETE; audit log records the revocation |
| Sliding window expired (detected at next request) | `SessionRepository::deleteByHash(token_hash)` — hard DELETE; return 401 |
| Absolute ceiling exceeded (detected at next request) | `SessionRepository::deleteByHash(token_hash)` — hard DELETE; return 401 |
| Background flush | `SessionRepository::pruneExpired()` — catches sessions that expired with no subsequent request |

---

### 4.2 Core Engine

#### 4.2.1 Variable Engine

**Header:** `core/VariableEngine.hpp`

**Responsibilities:**
- Tokenize record value templates containing `{{var_name}}` placeholders
- Resolve variables using a two-level lookup: zone-scoped first, then global
- Detect and reject circular references
- Validate resolved types match the record type (e.g., `IPv4` for A records)

**Algorithm — `expand(value, zone_id)`:**
```
1. Scan value for pattern \{\{([A-Za-z0-9_]+)\}\}
2. For each match token:
   a. Look up in zone-scoped variables WHERE zone_id = ?
   b. If not found, look up in global variables WHERE zone_id IS NULL
   c. If not found → throw UnresolvedVariableError
   d. Replace placeholder with the literal resolved value (no further expansion)
3. Return fully expanded string
```

> **Note:** Variable values must be flat literals. A variable's value may not itself contain `{{var}}` placeholders. Nested variable expansion is not supported.

**Limits:**
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
6. DeploymentRepository::create(zone_id, expanded_snapshot, actor)
7. DeploymentRepository::pruneOldSnapshots(zone_id)
8. Trigger GitOpsMirror::commit(zone_id)
9. Release per-zone mutex
```

**Snapshot Retention (`pruneOldSnapshots`):**
```
1. Resolve retention_count:
     - zones.deployment_retention if NOT NULL and >= 1
     - else DNS_DEPLOYMENT_RETENTION_COUNT env var (default: 10, minimum: 1)
2. DELETE FROM deployments
   WHERE zone_id = ?
     AND seq <= (
       SELECT seq FROM deployments
       WHERE zone_id = ?
       ORDER BY seq DESC
       OFFSET retention_count - 1
       LIMIT 1
     )
```

**Rollback Sequence (`RollbackEngine::apply`):**
```
1. DeploymentRepository::get(deployment_id) → snapshot JSONB
2. If cherry_pick_ids is empty:
     For each record in snapshot → RecordRepository::upsert(record)
   If cherry_pick_ids is non-empty:
     For each record_id in cherry_pick_ids:
       Find record in snapshot → RecordRepository::upsert(record)
3. AuditRepository::insert(operation='rollback', entity_id=deployment_id, actor)
4. Return: desired state updated; operator must preview and push to deploy
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
| `RecordRepository` | `dal/RecordRepository.hpp` | `records` table (raw templates); upsert for rollback restore |
| `VariableRepository` | `dal/VariableRepository.hpp` | `variables` table |
| `DeploymentRepository` | `dal/DeploymentRepository.hpp` | `deployments` table; snapshot create, get, list, prune |
| `AuditRepository` | `dal/AuditRepository.hpp` | `audit_log` table; insert, bulk-insert, `purgeOld(retention_days)` |
| `UserRepository` | `dal/UserRepository.hpp` | `users` + `groups` + `group_members` |
| `SessionRepository` | `dal/SessionRepository.hpp` | `sessions` table; `touch()`, `exists()`, `deleteByHash()`, `pruneExpired()` |
| `ApiKeyRepository` | `dal/ApiKeyRepository.hpp` | `api_keys` table; `scheduleDelete()`, `pruneScheduled()` |

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
- Master key: loaded from `DNS_MASTER_KEY` environment variable (32-byte hex string), or from the file at `DNS_MASTER_KEY_FILE` if the env var is unset (see §8 and §12.3)
- Each provider token is encrypted with a unique 12-byte random IV stored alongside the ciphertext
- Storage format: `base64(iv) + ":" + base64(ciphertext + tag)`
- After loading the master key into memory, the raw string is zeroed via `OPENSSL_cleanse()`

```cpp
class CryptoService {
public:
  std::string encrypt(const std::string& plaintext) const;
  std::string decrypt(const std::string& ciphertext) const;

  // SEC-01: API key generation and hashing (SHA-512 via OpenSSL EVP_sha512)
  static std::string generateApiKey();              // 32 random bytes → base64url (43 chars)
  static std::string hashApiKey(const std::string& raw_key); // → hex-encoded SHA-512
};
```

#### 4.6.2 JWT Signing Abstraction

**Header:** `security/IJwtSigner.hpp`

JWT signing is abstracted behind an interface to allow algorithm upgrades without changing call sites. The current implementation is HS256; RS256/ES256 are future options. (SEC-03)

```cpp
// security/IJwtSigner.hpp
class IJwtSigner {
public:
  virtual ~IJwtSigner() = default;
  virtual std::string      sign(const nlohmann::json& payload) const = 0;
  virtual nlohmann::json   verify(const std::string& token)    const = 0;
  // verify() throws AuthenticationError on invalid signature, expiry, or malformed token
};

// Concrete implementations:
// security/HmacJwtSigner.hpp  — HS256 (current; requires DNS_JWT_SECRET or DNS_JWT_SECRET_FILE)
// security/RsaJwtSigner.hpp   — RS256 (future; requires DNS_JWT_PRIVATE_KEY_FILE + DNS_JWT_PUBLIC_KEY_FILE)
// security/EcJwtSigner.hpp    — ES256 (future)
```

`AuthService` constructs the appropriate `IJwtSigner` at startup based on `DNS_JWT_ALGORITHM` (default: `HS256`).

#### 4.6.3 Authentication

**Header:** `security/AuthService.hpp`

The system supports four authentication methods simultaneously. The first three (local, OIDC, SAML) are interactive flows used by the Web GUI; they all produce a JWT session token upon success. The fourth (API key) is a non-interactive, stateless method used by the TUI and automated clients.

**Local Authentication (User/Group/Role):**
- Passwords hashed with Argon2id (via OpenSSL or `libsodium`)
- Users belong to one or more groups
- Groups are assigned roles: `admin`, `operator`, `viewer`
- Role resolution: highest-privilege role across all groups wins

**OIDC Authentication (SEC-06):**
- Implements Authorization Code Flow with PKCE
- Validates ID token signature against provider JWKS endpoint
- Maps OIDC `sub` claim to a local user record (auto-provisioned on first login if `DNS_OIDC_AUTO_PROVISION=true`)
- Configurable claim-to-role mapping via `DNS_OIDC_ROLE_CLAIM`
- **CSRF protection:** `state` parameter generated as 16 random bytes (base64url), stored in an HMAC-SHA256-signed cookie alongside `nonce`; validated on callback
- **Replay protection:** `nonce` (16 random bytes, base64url) bound to the OIDC session cookie and verified against the `nonce` claim in the returned ID token

**OIDC State Cookie Format:**
```
Cookie: oidc_state=<base64url(state||nonce||exp)>.<HMAC-SHA256(payload, DNS_JWT_SECRET)>
Attributes: HttpOnly; Secure; SameSite=Lax; Max-Age=600
```

**OIDC Callback Validation Sequence:**
```
GET /auth/oidc/callback?code=...&state=...
  1. Read oidc_state cookie → verify HMAC signature (reject if invalid or expired)
  2. Verify query param state == cookie state (reject if mismatch → log security event)
  3. Exchange code for id_token at IdP token endpoint
  4. Verify id_token.nonce == cookie nonce (reject if mismatch → log security event)
  5. Clear oidc_state cookie
  6. Issue JWT session
```

**SAML 2.0 Authentication (SEC-07):**
- SP-initiated SSO via HTTP POST binding
- Validates assertion signature against IdP metadata
- Maps SAML attribute to role via configurable attribute name (`DNS_SAML_ROLE_ATTR`)
- Auto-provisions users on first login if `DNS_SAML_AUTO_PROVISION=true`
- **Replay protection:** In-memory `SamlReplayCache` tracks seen assertion IDs with TTL eviction matching each assertion's `NotOnOrAfter` window

**SAML Replay Cache:**
```cpp
// security/SamlReplayCache.hpp
class SamlReplayCache {
public:
  // Returns false if assertion_id was already seen (replay detected)
  bool checkAndInsert(const std::string& assertion_id,
                      std::chrono::system_clock::time_point not_on_or_after);
private:
  std::unordered_map<std::string,
                     std::chrono::system_clock::time_point> cache_;
  std::mutex mutex_;
  void evictExpired();  // called on each insert; removes entries where not_on_or_after < now()
};
```

> **Multi-instance note:** `SamlReplayCache` is process-local. Multi-instance deployments require a shared external cache (e.g., Redis). Document this in the deployment guide.

**API Key Authentication (SEC-01):**
- Pre-provisioned long-lived tokens created by an admin via `POST /api/v1/auth/keys`
- Raw key generated as 32 cryptographically random bytes (via `RAND_bytes()`), base64url-encoded → 43-character key
- Raw key is shown to the admin exactly once at creation time; only the **SHA-512 hash** is stored in the `api_keys` table
- Sent on every request as `X-API-Key: <raw_key>`; no session is created, no JWT is issued
- Optional expiry (`expires_at`); revocable at any time via `DELETE /api/v1/auth/keys/{id}`
- Used exclusively by the TUI; the TUI reads the key from `DNS_TUI_API_KEY` env var or `~/.config/dns-orchestrator/credentials` (mode `0600`)
- RBAC is enforced identically to other auth methods: the key is associated with a user, and that user's role applies

**Session Tokens (JWT — interactive flows only):**
- JWT signed with algorithm specified by `DNS_JWT_ALGORITHM` (default: `HS256`) via `IJwtSigner`
- Signing secret loaded from `DNS_JWT_SECRET` or `DNS_JWT_SECRET_FILE` (see §12.3)
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
| Purge audit log | ✗ | ✗ | ✓ |
| Export audit log (NDJSON) | ✗ | ✗ | ✓ |

#### 4.6.4 HTTP Security Headers (SEC-12)

`ApiServer` applies a response middleware to **all routes** that injects the following headers:

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Content-Security-Policy: default-src 'self'
```

The `Server:` response header is suppressed (Restbed's default server identification is removed).

#### 4.6.5 Input Validation Limits (SEC-11)

**HTTP Layer (Restbed configuration):**
- Maximum request body size: **64 KB** — requests exceeding this return `413 Payload Too Large`

**Application Layer (enforced in route handlers):**

| Field | Maximum Length |
|-------|---------------|
| Zone name | 253 characters (DNS specification limit) |
| Record name | 253 characters |
| Record value / template | 4,096 characters |
| Variable name | 64 characters |
| Variable value | 4,096 characters |
| Provider name | 128 characters |
| Username | 128 characters |
| Password (input) | 1,024 characters |
| API key description | 512 characters |
| Group name | 128 characters |
| Audit query `identity` filter | 128 characters |

**SQL Injection Prevention:**
All SQL is executed via `libpqxx` parameterized queries (`pqxx::work::exec_params()`). Raw string interpolation of user input into SQL is **prohibited** throughout the codebase. This is a non-negotiable constraint enforced in code review.

---

### 4.7 TUI Layer

> **Note:** The TUI client is maintained as a separate project with its own repository. It communicates exclusively with the REST API defined in §6 — it has no direct database access or shared code with the server beyond the API contract.
>
> For the full TUI design — screen hierarchy, key bindings, FTXUI components, and `ApiKeyConfig` loading — see the [TUI Client Design Document](docs/TUI_DESIGN.md).

**Summary:**

- **Framework:** FTXUI
- **Authentication:** API key only (`X-API-Key` header); no interactive login screen
- **Communication:** Stateless HTTP requests to the same REST API as the Web GUI
- **Key loading:** `DNS_TUI_API_KEY` env var or `~/.config/dns-orchestrator/credentials` (mode `0600`)

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
| Maintenance tasks | Serialized within the `MaintenanceScheduler` thread; never use the `ThreadPool` worker queue |

---

### 4.9 Maintenance Scheduler

**Header:** `core/MaintenanceScheduler.hpp`

**Responsibilities:**
- Run periodic background tasks (audit purge, session flush, API key cleanup) on configurable intervals
- Isolate maintenance I/O from the request-handling `ThreadPool` so that slow DB deletes never starve API workers
- Provide independent fault isolation: a failing task is caught and logged without aborting other tasks or the scheduler loop

**Design:**
```cpp
// core/MaintenanceScheduler.hpp
class MaintenanceScheduler {
public:
  // Register a named task to run on the given interval.
  // Must be called before start().
  void schedule(const std::string& name,
                std::chrono::seconds interval,
                std::function<void()> task);

  void start();  // launches the dedicated background std::jthread
  void stop();   // signals the thread to exit; called during graceful shutdown
private:
  struct Task {
    std::string                              name;
    std::chrono::seconds                     interval;
    std::function<void()>                    fn;
    std::chrono::steady_clock::time_point    next_run;
  };
  std::vector<Task>        tasks_;
  std::jthread             thread_;
  std::mutex               mutex_;
  std::condition_variable  cv_;
};
```

**Scheduling Algorithm:**
```
loop:
  now = steady_clock::now()
  for each task in tasks_:
    if now >= task.next_run:
      try { task.fn() } catch (...) { log error; }
      task.next_run = now + task.interval
  sleep until min(task.next_run) across all tasks
```

**Registered Tasks (initialized at startup — see §11.4):**

| Task | Method | Interval Env Var | Default | Condition |
|------|--------|-----------------|---------|-----------|
| Audit log purge | `AuditRepository::purgeOld(retention_days)` | `DNS_AUDIT_PURGE_INTERVAL_SECONDS` | `86400` (24 h) | Only registered if `DNS_AUDIT_DB_URL` is set |
| Session flush | `SessionRepository::pruneExpired()` | `DNS_SESSION_CLEANUP_INTERVAL_SECONDS` | `3600` (1 h) | Always registered |
| API key cleanup | `ApiKeyRepository::pruneScheduled()` | `DNS_API_KEY_CLEANUP_INTERVAL_SECONDS` | `3600` (1 h) | Always registered |

**`AuditRepository::purgeOld()` result:**
```cpp
struct PurgeResult {
  int64_t                                          deleted_count;
  std::optional<std::chrono::system_clock::time_point> oldest_remaining;
};
PurgeResult purgeOld(int retention_days);
```
After each scheduled purge, a single `audit_log` entry is written by the system identity:
```
{ operation: "system_purge", identity: "system",
  new_value: { deleted: N, oldest_remaining: "<timestamp>" } }
```

---

## 5. PostgreSQL Schema

### 5.1 Enumerations

```sql
CREATE TYPE provider_type   AS ENUM ('powerdns', 'cloudflare', 'digitalocean');
CREATE TYPE variable_type   AS ENUM ('ipv4', 'ipv6', 'target', 'string');
CREATE TYPE variable_scope  AS ENUM ('global', 'zone');
CREATE TYPE user_role       AS ENUM ('admin', 'operator', 'viewer');
CREATE TYPE auth_method     AS ENUM ('local', 'oidc', 'saml', 'api_key');
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
  id                   BIGSERIAL PRIMARY KEY,
  name                 TEXT NOT NULL,               -- e.g. "example.com"
  view_id              BIGINT NOT NULL REFERENCES views(id) ON DELETE RESTRICT,
  deployment_retention INTEGER,                     -- NULL = use DNS_DEPLOYMENT_RETENTION_COUNT; must be >= 1 if set
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
  zone_id    BIGINT REFERENCES zones(id) ON DELETE CASCADE,  -- NULL = global
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (name, zone_id),                 -- zone_id NULL treated as global namespace
  CHECK (scope = 'global' AND zone_id IS NULL
      OR scope = 'zone'   AND zone_id IS NOT NULL)
);

-- DNS records (stores raw templates with {{var}} placeholders)
-- This table is the authoritative desired state for each zone.
-- Records are written immediately on operator edit; no staging intermediary.
CREATE TABLE records (
  id             BIGSERIAL PRIMARY KEY,
  zone_id        BIGINT NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
  name           TEXT NOT NULL,           -- relative or FQDN
  type           TEXT NOT NULL,           -- A, AAAA, CNAME, MX, TXT, SRV, NS, PTR
  ttl            INTEGER NOT NULL DEFAULT 300,
  value_template TEXT NOT NULL,           -- may contain {{var_name}} tokens
  priority       INTEGER NOT NULL DEFAULT 0,
  last_audit_id  BIGINT REFERENCES audit_log(id),  -- links to the audit entry that produced this state
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Deployment history: snapshot of the fully-expanded zone state at each successful push.
-- Older snapshots are pruned automatically per the retention policy (DNS_DEPLOYMENT_RETENTION_COUNT or zones.deployment_retention).
-- Used for rollback (full zone or cherry-picked records) and drift comparison.
CREATE TABLE deployments (
  id           BIGSERIAL PRIMARY KEY,
  zone_id      BIGINT NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
  deployed_by  BIGINT NOT NULL REFERENCES users(id),
  deployed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  -- Monotonically increasing sequence per zone; used for retention pruning
  seq          BIGINT NOT NULL,
  -- Full expanded zone snapshot at push time (array of fully-resolved records)
  snapshot     JSONB NOT NULL
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
-- expires_at:          sliding-window deadline; extended by DNS_JWT_TTL_SECONDS on each validated request
-- absolute_expires_at: hard ceiling set at login (created_at + DNS_SESSION_ABSOLUTE_TTL_SECONDS); never extended
-- last_seen_at:        updated on each validated request alongside expires_at
-- No revoked flag: revocation and logout perform an immediate hard DELETE.
--   The audit_log records the logout/revocation event for forensic purposes.
CREATE TABLE sessions (
  id                   BIGSERIAL PRIMARY KEY,
  user_id              BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash           TEXT NOT NULL UNIQUE,       -- SHA-256 of JWT
  expires_at           TIMESTAMPTZ NOT NULL,        -- sliding window; clamped to absolute_expires_at
  absolute_expires_at  TIMESTAMPTZ NOT NULL,        -- hard ceiling; never extended after creation
  last_seen_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- API keys (used by TUI and automated clients; no session created)
-- delete_after: set to NOW() + DNS_API_KEY_CLEANUP_GRACE_SECONDS when a key is revoked or found expired.
--   The background ApiKeyRepository::pruneScheduled() deletes rows where delete_after < NOW().
--   NULL means the key is active.
CREATE TABLE api_keys (
  id           BIGSERIAL PRIMARY KEY,
  user_id      BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  key_hash     TEXT NOT NULL UNIQUE,       -- SHA-512 of the raw key (SEC-01); raw key shown once at creation
  description  TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at   TIMESTAMPTZ,               -- NULL = never expires
  revoked      BOOLEAN NOT NULL DEFAULT FALSE,
  delete_after TIMESTAMPTZ                -- NULL = active; set on revocation or expiry detection
);
```

### 5.3 Indexes

```sql
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
**Authentication:** `Authorization: Bearer <jwt>` or `X-API-Key: <key>` on all endpoints except `/auth/local/login`, `/auth/oidc/*`, `/auth/saml/*`, and `/health`

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
| `GET`  | `/auth/keys` | admin | List all API keys (key_hash and metadata; raw key never returned) |
| `POST` | `/auth/keys` | admin | Create a new API key; returns raw key **once** in response |
| `GET`  | `/auth/keys/me` | any | List API keys belonging to the authenticated user |
| `DELETE` | `/auth/keys/{id}` | admin | Revoke an API key immediately |

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
| `POST`   | `/zones/{id}/records` | operator | Create a record (immediately becomes desired state) |
| `GET`    | `/zones/{id}/records/{rid}` | viewer | Get record by ID |
| `PUT`    | `/zones/{id}/records/{rid}` | operator | Update a record (immediately becomes desired state) |
| `DELETE` | `/zones/{id}/records/{rid}` | operator | Delete a record (immediately removed from desired state) |
| `POST`   | `/zones/{id}/preview` | viewer | Run diff preview for a zone; compares desired state vs. live provider; returns `PreviewResult` |
| `POST`   | `/zones/{id}/push` | operator | Execute deployment for a zone; pushes desired state to provider and creates a deployment snapshot |

### 6.6 Variables

| Method | Path | Role Required | Description |
|--------|------|---------------|-------------|
| `GET`    | `/variables` | viewer | List variables (filterable by `?scope=global` or `?zone_id=`) |
| `POST`   | `/variables` | operator | Create a variable |
| `GET`    | `/variables/{id}` | viewer | Get variable by ID |
| `PUT`    | `/variables/{id}` | operator | Update a variable |
| `DELETE` | `/variables/{id}` | operator | Delete a variable |

### 6.7 Deployment History and Rollback

| Method | Path | Role Required | Description |
|--------|------|---------------|-------------|
| `GET`    | `/zones/{id}/deployments` | viewer | List deployment history for a zone (ordered by `seq DESC`) |
| `GET`    | `/zones/{id}/deployments/{did}` | viewer | Get a specific deployment snapshot |
| `GET`    | `/zones/{id}/deployments/{did}/diff` | viewer | Diff snapshot vs. current desired state in `records`; returns `PreviewResult` |
| `POST`   | `/zones/{id}/deployments/{did}/rollback` | operator | Restore snapshot into `records` (full zone or cherry-picked records); does not push automatically |

**Preview Response Shape** (returned by `POST /zones/{id}/preview` and `GET /zones/{id}/deployments/{did}/diff`):
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

**Rollback Request Body:**
```json
{
  "cherry_pick_ids": [42, 57]
}
```
Omit `cherry_pick_ids` (or pass an empty array) to restore the full zone snapshot. Rollback only updates the `records` table (desired state); the operator must run `POST /zones/{id}/preview` and `POST /zones/{id}/push` to deploy the restored state.

**Deployment Snapshot Shape** (stored in `deployments.snapshot` JSONB):
```json
{
  "zone": "example.com",
  "view": "external",
  "provider": "cloudflare",
  "deployed_at": "2026-02-27T01:00:00Z",
  "deployed_by": "alice",
  "records": [
    {
      "record_id": 42,
      "name": "www.example.com.",
      "type": "A",
      "ttl": 300,
      "value": "203.0.113.10",
      "priority": 0
    }
  ]
}
```
Note: `value` in the snapshot is the **fully expanded** value (all variables resolved), not the raw template.

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
| `GET`    | `/audit` | viewer | Query audit log (filterable by `?entity_type=`, `?identity=`, `?from=`, `?to=`) |
| `GET`    | `/audit/export` | admin | Stream full audit log as NDJSON (`application/x-ndjson`); supports `?from=` and `?to=` ISO 8601 params (SEC-05) |
| `DELETE` | `/audit/purge` | admin | Purge audit entries older than `DNS_AUDIT_RETENTION_DAYS`; returns `{"deleted": N, "oldest_remaining": "<timestamp>"}` (SEC-04) |

> **SIEM Integration:** Production deployments should configure an external SIEM (Splunk, Elastic, Datadog, etc.) to call `GET /audit/export` on a schedule before invoking `DELETE /audit/purge`. This provides tamper-evident long-term retention outside the application database.

### 6.10 Health

| Method | Path | Auth Required | Description |
|--------|------|---------------|-------------|
| `GET` | `/health` | No | Returns `{"status":"ok"}` or `{"status":"degraded","detail":"..."}` |

---

## 7. Data Flow Diagrams

### 7.1 Edit → Preview → Deploy → Rollback Pipeline

```
User
 │
 ├─[1] PUT /zones/{id}/records/{rid}  (operator)
 │      └─ Single transaction:
 │           ├─ AuditRepository::insert(old_value, new_value, actor) → audit_id
 │           └─ RecordRepository::update(value_template, last_audit_id=audit_id)
 │              records table is now the desired state; no staging write
 │
 ├─[2] POST /zones/{id}/preview  (viewer)
 │      └─ DiffEngine::preview(zone_id)
 │           ├─ RecordRepository::listByZone(zone_id) → desired state (raw templates)
 │           ├─ VariableEngine::expand() for each record
 │           ├─ IProvider::listRecords(zone_name) → live state from provider
 │           └─ Compute diff → return PreviewResult
 │
 ├─[3] POST /zones/{id}/push  (operator)
 │      └─ DeploymentEngine::push(zone_id, purge_drift, actor)
 │           ├─ Acquire per-zone mutex
 │           ├─ Re-run DiffEngine::preview() (freshness guard)
 │           ├─ For each diff: IProvider::createRecord / updateRecord / deleteRecord
 │           ├─ On any provider error → rollback attempted changes, release mutex, throw
 │           ├─ AuditRepository::bulkInsert(push audit entries)
 │           ├─ DeploymentRepository::create(zone_id, expanded_snapshot, actor)
 │           ├─ DeploymentRepository::pruneOldSnapshots(zone_id)
 │           ├─ GitOpsMirror::commit(zone_id, actor)
 │           └─ Release per-zone mutex
 │
 └─[4] POST /zones/{id}/deployments/{did}/rollback  (operator)
        └─ RollbackEngine::apply(zone_id, deployment_id, cherry_pick_ids)
             ├─ DeploymentRepository::get(deployment_id) → snapshot JSONB
             ├─ If cherry_pick_ids empty: RecordRepository::upsert() for all snapshot records
             │  If cherry_pick_ids non-empty: RecordRepository::upsert() for selected record_ids only
             ├─ AuditRepository::insert(operation='rollback', entity_id=deployment_id, actor)
             └─ Return: desired state restored; operator must preview and push to deploy
```

### 7.2 Variable Expansion Flow

```
record.value_template = "{{LB_VIP}}"
         │
         ▼
VariableEngine::expand("{{LB_VIP}}", zone_id=42)
         │
         ├─ Tokenize → ["LB_VIP"]
         ├─ VariableRepository::findByName("LB_VIP", zone_id=42)
         │     → not found in zone scope
         ├─ VariableRepository::findByName("LB_VIP", zone_id=NULL)
         │     → found: value="203.0.113.10", scope=global
         └─ Replace placeholder → "203.0.113.10"
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

Every Authenticated Request (JWT path):
  Authorization: Bearer <jwt>
    └─ AuthMiddleware::validateJwt(jwt)
         ├─ Verify JWT signature (HS256, DNS_JWT_SECRET)
         ├─ Check exp not exceeded
         ├─ SessionRepository::isRevoked(SHA256(jwt))
         └─ Inject RequestContext {auth_method="local"|"oidc"|"saml"} into handler

API Key Authentication (TUI / automated clients):
  TUI Startup:
    └─ ApiKeyConfig::load()
         ├─ Read DNS_TUI_API_KEY env var
         └─ Fallback: read ~/.config/dns-orchestrator/credentials (mode 0600, line: api_key=<value>)

  GET /auth/me  [X-API-Key: <raw_key>]
    └─ AuthMiddleware::validateApiKey(raw_key)
         ├─ SHA-256(raw_key) → key_hash
         ├─ ApiKeyRepository::findByHash(key_hash)
         ├─ Check revoked=false
         ├─ Check expires_at IS NULL OR expires_at > NOW()
         ├─ UserRepository::findById(user_id) → username
         ├─ GroupRepository::getHighestRole(user_id) → role
         └─ Inject RequestContext {auth_method="api_key"} into handler

  On success → TuiApp launches MainScreen directly (no LoginScreen)
  On failure → TuiApp prints error to stderr and exits(1)

  Every Subsequent TUI Request:
    X-API-Key: <raw_key>   (stateless; validated fresh on every request)
```

---

## 8. Configuration and Environment Variables

All configuration is provided via environment variables. No config files are required at runtime (though a `.env` file may be used in development).

For sensitive secrets (`DNS_MASTER_KEY`, `DNS_JWT_SECRET`), a `_FILE` variant is supported: if the base variable is unset, the application reads the secret from the file path specified in the `_FILE` variable. This is the recommended pattern for production deployments using Docker secrets or Kubernetes secret volume mounts (see §12.3).

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DNS_DB_URL` | Yes | — | PostgreSQL connection string for the `dns_app` role (`postgresql://user:pass@host:5432/dbname`) |
| `DNS_DB_POOL_SIZE` | No | `10` | Number of DB connections in the pool |
| `DNS_AUDIT_DB_URL` | No | — | PostgreSQL connection string for the `dns_audit_admin` role; required to use `DELETE /audit/purge` (SEC-13) |
| `DNS_MASTER_KEY` | Yes* | — | 32-byte hex string for AES-256-GCM credential encryption (*or set `DNS_MASTER_KEY_FILE`) |
| `DNS_MASTER_KEY_FILE` | Yes* | — | Path to file containing the 32-byte hex master key (*used if `DNS_MASTER_KEY` is unset; SEC-02) |
| `DNS_JWT_SECRET` | Yes* | — | Secret for JWT signing (*or set `DNS_JWT_SECRET_FILE`) |
| `DNS_JWT_SECRET_FILE` | Yes* | — | Path to file containing the JWT secret (*used if `DNS_JWT_SECRET` is unset; SEC-02) |
| `DNS_JWT_ALGORITHM` | No | `HS256` | JWT signing algorithm; `HS256` now; `RS256`/`ES256` supported in future (SEC-03) |
| `DNS_JWT_TTL_SECONDS` | No | `28800` | JWT expiry in seconds (default 8 hours) |
| `DNS_HTTP_PORT` | No | `8080` | Port for the Restbed HTTP server |
| `DNS_HTTP_THREADS` | No | `4` | Restbed worker thread count |
| `DNS_THREAD_POOL_SIZE` | No | `hw_concurrency` | Core engine thread pool size |
| `DNS_GIT_REMOTE_URL` | No | — | Git remote URL for GitOps mirror (disabled if unset) |
| `DNS_GIT_LOCAL_PATH` | No | `/var/dns-orchestrator/repo` | Local path for Git mirror clone |
| `DNS_GIT_SSH_KEY_PATH` | No | — | Path to SSH private key for Git push auth |
| `DNS_GIT_KNOWN_HOSTS_FILE` | No | — | Path to known_hosts file for SSH host verification (future implementation; SEC-09) |
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
| `DNS_TUI_API_KEY` | No | — | API key for TUI authentication; if unset, TUI reads `~/.config/dns-orchestrator/credentials` |
| `DNS_AUDIT_STDOUT` | No | `false` | Mirror audit log entries to stdout (for Docker log collection) |
| `DNS_AUDIT_RETENTION_DAYS` | No | `365` | Minimum age in days for audit records eligible for purge via `DELETE /audit/purge` (SEC-04) |
| `DNS_AUDIT_PURGE_INTERVAL_SECONDS` | No | `86400` | How often `MaintenanceScheduler` runs the automatic audit log purge. Only active if `DNS_AUDIT_DB_URL` is set. Set to `0` to disable scheduled purge entirely. |
| `DNS_SESSION_ABSOLUTE_TTL_SECONDS` | No | `86400` | Hard ceiling for any session (24 h). Set at login; never extended by activity. Forces re-login after this duration regardless of the sliding window. Must be `>= DNS_JWT_TTL_SECONDS`. |
| `DNS_SESSION_CLEANUP_INTERVAL_SECONDS` | No | `3600` | How often `MaintenanceScheduler` flushes expired sessions from the `sessions` table. |
| `DNS_API_KEY_CLEANUP_GRACE_SECONDS` | No | `300` | Grace period (in seconds) after a key is revoked or found expired before its row becomes eligible for deletion. Allows in-flight requests using that key to receive a proper 401 rather than a "key not found" error. |
| `DNS_API_KEY_CLEANUP_INTERVAL_SECONDS` | No | `3600` | How often `MaintenanceScheduler` deletes API key rows whose `delete_after` timestamp has passed. |
| `DNS_DEPLOYMENT_RETENTION_COUNT` | No | `10` | Number of deployment snapshots to retain per zone. Must be `>= 1`; a value of `0` is invalid and will cause a fatal startup error. Overridden per zone by `zones.deployment_retention`. |
| `DNS_TLS_CERT_FILE` | No | — | Path to PEM TLS certificate chain (future native TLS support; SEC-08) |
| `DNS_TLS_KEY_FILE` | No | — | Path to PEM TLS private key (future native TLS support; SEC-08) |
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
| Provider API error during push | Rollback attempted provider changes; return 502; log to audit |
| Zone already being pushed | Return 409 `deployment_locked` |
| Git mirror push fails | Log warning to audit; push is still marked successful |
| Deployment snapshot not found | Return 404 `deployment_not_found` |
| Rollback cherry-pick ID not in snapshot | Return 422 `invalid_cherry_pick_id` with list of valid IDs |
| DB connection unavailable | Return 503; log to stderr |
| JWT expired | Return 401 `token_expired` |
| JWT revoked | Return 401 `token_revoked` |
| API key not found | Return 401 `invalid_api_key` |
| API key revoked | Return 401 `api_key_revoked` |
| API key expired | Return 401 `api_key_expired` |

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
│   │       ├── DeploymentRoutes.hpp
│   │       ├── AuditRoutes.hpp
│   │       └── HealthRoutes.hpp
│   ├── core/
│   │   ├── VariableEngine.hpp
│   │   ├── DiffEngine.hpp
│   │   ├── DeploymentEngine.hpp
│   │   ├── RollbackEngine.hpp
│   │   ├── MaintenanceScheduler.hpp
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
│   │   ├── DeploymentRepository.hpp
│   │   ├── AuditRepository.hpp
│   │   ├── UserRepository.hpp
│   │   ├── SessionRepository.hpp
│   │   └── ApiKeyRepository.hpp
│   ├── gitops/
│   │   └── GitOpsMirror.hpp
│   └── security/
│       ├── CryptoService.hpp
│       ├── AuthService.hpp
│       ├── IJwtSigner.hpp
│       ├── HmacJwtSigner.hpp
│       └── SamlReplayCache.hpp
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
│   │   ├── RollbackEngine.cpp
│   │   ├── MaintenanceScheduler.cpp
│   │   └── ThreadPool.cpp
│   ├── providers/
│   │   ├── ProviderFactory.cpp
│   │   ├── PowerDnsProvider.cpp
│   │   ├── CloudflareProvider.cpp
│   │   └── DigitalOceanProvider.cpp
│   ├── dal/
│   │   ├── ConnectionPool.cpp
│   │   └── *Repository.cpp             # includes ApiKeyRepository.cpp
│   ├── gitops/
│   │   └── GitOpsMirror.cpp
│   └── security/
│       ├── CryptoService.cpp
│       ├── AuthService.cpp
│       ├── HmacJwtSigner.cpp
│       └── SamlReplayCache.cpp
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
  libspdlog-dev \
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
   - For DNS_MASTER_KEY: use env var if set, else read DNS_MASTER_KEY_FILE; fatal if neither set
   - For DNS_JWT_SECRET: use env var if set, else read DNS_JWT_SECRET_FILE; fatal if neither set
   - Zero raw secret strings from memory after loading (OPENSSL_cleanse)
   - Validate DNS_DEPLOYMENT_RETENTION_COUNT >= 1; fatal if set to 0 or a negative value
   - Validate DNS_SESSION_ABSOLUTE_TTL_SECONDS >= DNS_JWT_TTL_SECONDS; fatal if not
2. Initialize CryptoService with DNS_MASTER_KEY
3. Construct IJwtSigner based on DNS_JWT_ALGORITHM (default: HmacJwtSigner/HS256)
4. Initialize ConnectionPool (DNS_DB_URL, DNS_DB_POOL_SIZE)
5. Run pending DB migrations (scripts/db/*.sql in order)
6. Initialize GitOpsMirror (if DNS_GIT_REMOTE_URL is set): git clone or git pull
7. Initialize ThreadPool (DNS_THREAD_POOL_SIZE workers)
7a. Initialize MaintenanceScheduler (see §4.9):
    - Register SessionRepository::pruneExpired()   every DNS_SESSION_CLEANUP_INTERVAL_SECONDS
    - Register ApiKeyRepository::pruneScheduled()  every DNS_API_KEY_CLEANUP_INTERVAL_SECONDS
    - Register AuditRepository::purgeOld(DNS_AUDIT_RETENTION_DAYS)
        every DNS_AUDIT_PURGE_INTERVAL_SECONDS
        (only if DNS_AUDIT_DB_URL is set; log startup warning if unset)
    - Start MaintenanceScheduler background thread
8. Initialize SamlReplayCache (if SAML is enabled)
9. Initialize ProviderFactory
10. Register all API routes on ApiServer (with security headers middleware)
11. Start Restbed HTTP server on DNS_HTTP_PORT
12. Log "dns-orchestrator ready" to stdout
```

---

## 12. Security Hardening Reference

This section documents operational security requirements and deployment constraints. See [`plans/SECURITY_PLAN.md`](plans/SECURITY_PLAN.md) for the full rationale behind each decision.

### 12.1 Deployment Security Requirements

> **These are hard requirements. Violating them creates critical security vulnerabilities.**

| Requirement | Detail |
|-------------|--------|
| **TLS termination** | The application serves plain HTTP on `DNS_HTTP_PORT`. It MUST be deployed behind a TLS-terminating reverse proxy (nginx, Caddy, Traefik). Direct exposure of port 8080 to untrusted networks is prohibited. |
| **HTTPS-only cookies** | The OIDC `oidc_state` cookie is set with `Secure` attribute. The reverse proxy must enforce HTTPS; HTTP access must redirect to HTTPS. |
| **Non-root process** | The container runs as the `dns-orchestrator` system user (no-login, no home directory). Do not override `USER` in derived images. |
| **Secret injection** | `DNS_MASTER_KEY` and `DNS_JWT_SECRET` must be injected via a secrets manager (HashiCorp Vault, AWS Secrets Manager, Kubernetes Secrets, Docker Secrets). Do not hardcode secrets in `docker-compose.yml` or environment files committed to version control. |
| **Network isolation** | PostgreSQL must not be exposed to the public internet. Use Docker networks or Kubernetes NetworkPolicy to restrict DB access to the application container only. |

**Future native TLS (not yet implemented):**
When `DNS_TLS_CERT_FILE` and `DNS_TLS_KEY_FILE` are both set, a future implementation will configure Restbed's SSL context for direct TLS termination without a reverse proxy.

---

### 12.2 PostgreSQL Least-Privilege Roles

Two PostgreSQL roles are required. The application uses `dns_app` for all normal operations; `dns_audit_admin` is used exclusively by the `DELETE /api/v1/audit/purge` endpoint.

```sql
-- Role 1: Application runtime user (dns_app)
-- Used by DNS_DB_URL
CREATE ROLE dns_app LOGIN PASSWORD '<strong-password>';
GRANT CONNECT ON DATABASE dns_orchestrator TO dns_app;
GRANT USAGE ON SCHEMA public TO dns_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO dns_app;
REVOKE DELETE ON audit_log FROM dns_app;   -- audit_log is insert-only for the app
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO dns_app;

-- Role 2: Audit purge user (dns_audit_admin)
-- Used by DNS_AUDIT_DB_URL (only required if audit purge endpoint is used)
CREATE ROLE dns_audit_admin LOGIN PASSWORD '<strong-password>';
GRANT CONNECT ON DATABASE dns_orchestrator TO dns_audit_admin;
GRANT USAGE ON SCHEMA public TO dns_audit_admin;
GRANT SELECT, DELETE ON audit_log TO dns_audit_admin;
```

> **Note:** `dns_app` cannot delete audit log rows. Only `dns_audit_admin` can, and only via the authenticated `DELETE /api/v1/audit/purge` endpoint (admin role required). This provides a two-factor tamper barrier: database privilege + application RBAC.

---

### 12.3 Secret Management

**Loading Priority (for `DNS_MASTER_KEY` and `DNS_JWT_SECRET`):**

```
1. If DNS_MASTER_KEY is set in environment → use it
2. Else if DNS_MASTER_KEY_FILE is set → read file, trim whitespace, use contents
3. Else → fatal startup error
```

**File-based secret requirements:**
- File must be mode `0400` (owner read-only)
- File contents are read once at startup; file descriptor is closed immediately after
- Raw secret string is zeroed from memory via `OPENSSL_cleanse()` after loading into `CryptoService`

**Recommended production pattern (Docker Secrets):**
```yaml
# docker-compose.yml (production)
services:
  app:
    image: dns-orchestrator:latest
    secrets:
      - master_key
      - jwt_secret
    environment:
      DNS_MASTER_KEY_FILE: /run/secrets/master_key
      DNS_JWT_SECRET_FILE: /run/secrets/jwt_secret
      DNS_DB_URL: postgresql://dns_app:<pass>@db:5432/dns_orchestrator

secrets:
  master_key:
    external: true   # managed by Docker Swarm secrets or external vault
  jwt_secret:
    external: true
```

---

### 12.4 Rate Limiting (Reverse Proxy)

The application does not implement in-process rate limiting. The reverse proxy **must** enforce rate limits on authentication endpoints to prevent brute-force attacks.

**nginx:**
```nginx
limit_req_zone $binary_remote_addr zone=dns_auth:10m rate=5r/m;

server {
  location /api/v1/auth/local/login {
    limit_req zone=dns_auth burst=3 nodelay;
    limit_req_status 429;
    proxy_pass http://dns-orchestrator:8080;
  }

  location /api/v1/ {
    proxy_pass http://dns-orchestrator:8080;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
  }
}
```

**Caddy:**
```caddy
dns-orchestrator.example.com {
  @auth_login path /api/v1/auth/local/login
  rate_limit @auth_login 5r/m

  reverse_proxy /api/v1/* dns-orchestrator:8080
}
```

**Traefik:**
```yaml
middlewares:
  auth-ratelimit:
    rateLimit:
      average: 5
      period: 1m
      burst: 3

routers:
  dns-auth:
    rule: "Path(`/api/v1/auth/local/login`)"
    middlewares:
      - auth-ratelimit
    service: dns-orchestrator
```

---

### 12.5 Git Remote Security

When `DNS_GIT_REMOTE_URL` is configured, the following security requirements apply:

| Requirement | Detail |
|-------------|--------|
| **Deploy key scope** | The SSH key at `DNS_GIT_SSH_KEY_PATH` must be a repository-scoped deploy key, not a user key. It must have write access to exactly one repository. |
| **Key permissions** | The SSH private key file must be mode `0400` (owner read-only). |
| **Remote access** | The Git remote should be on an internal network or accessed via VPN where possible. |
| **Host verification** | `DNS_GIT_KNOWN_HOSTS_FILE` is reserved for a future implementation of SSH host fingerprint verification via `libgit2` `certificate_check` callback. When implemented, connections to hosts not listed in the known_hosts file will be rejected. |
| **Force-push** | The GitOps mirror uses force-push to resolve conflicts (DB state always wins). The remote repository should be configured to allow force-push only from the deploy key, and to protect the branch from deletion. |

> **Multi-instance SAML note:** The `SamlReplayCache` is process-local (in-memory). If the application is deployed with multiple instances behind a load balancer, a shared external cache (e.g., Redis) must be used to prevent assertion replay across instances. This is a future enhancement; document in your deployment runbook if running multi-instance.