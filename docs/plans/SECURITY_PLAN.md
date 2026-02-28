# Security Hardening Plan — DNS Orchestrator

> **Status:** Approved  
> **Date:** 2026-02-26  
> **Scope:** Pre-implementation security review of [`ARCHITECTURE.md`](../ARCHITECTURE.md)  
> **Outcome:** 14 security items identified; all decisions captured below and reflected in `ARCHITECTURE.md`

---

## Table of Contents

1. [Threat Model Summary](#1-threat-model-summary)
2. [Findings and Decisions](#2-findings-and-decisions)
  - [C-1 — API Key Hashing (SEC-01)](#c-1--api-key-hashing-sec-01)
  - [C-2 — OIDC CSRF / Replay (SEC-06)](#c-2--oidc-csrf--replay-sec-06)
  - [C-3 — SAML Assertion Replay (SEC-07)](#c-3--saml-assertion-replay-sec-07)
  - [H-1 — Secret Management (SEC-02)](#h-1--secret-management-sec-02)
  - [H-2 — TLS Termination (SEC-08)](#h-2--tls-termination-sec-08)
  - [H-3 — Audit Log Retention (SEC-04 + SEC-05)](#h-3--audit-log-retention-sec-04--sec-05)
  - [M-1 — JWT Algorithm Abstraction (SEC-03)](#m-1--jwt-algorithm-abstraction-sec-03)
  - [M-2 — Security Response Headers (SEC-12)](#m-2--security-response-headers-sec-12)
  - [M-3 — Input Size Limits (SEC-11)](#m-3--input-size-limits-sec-11)
  - [M-4 — Git SSH Host Verification (SEC-09)](#m-4--git-ssh-host-verification-sec-09)
  - [L-1 — Rate Limiting (SEC-10)](#l-1--rate-limiting-sec-10)
  - [L-2 — PostgreSQL Least Privilege (SEC-13)](#l-2--postgresql-least-privilege-sec-13)
3. [New Environment Variables](#3-new-environment-variables)
4. [New API Endpoints](#4-new-api-endpoints)
5. [Implementation Checklist](#5-implementation-checklist)

---

## 1. Threat Model Summary

The DNS Orchestrator is a **critical infrastructure control plane**. A successful attack could:

- Redirect traffic by modifying DNS records (A, CNAME, MX)
- Exfiltrate internal network topology via split-horizon zone data
- Gain persistent access to cloud provider APIs via stolen encrypted tokens
- Tamper with audit logs to cover tracks

**Trust Boundaries:**

| Boundary | Risk |
|----------|------|
| Internet → Reverse Proxy | DDoS, brute-force, TLS stripping |
| Reverse Proxy → App (HTTP) | Credential interception if proxy misconfigured |
| App → PostgreSQL | SQL injection, credential theft, audit tampering |
| App → Provider APIs | Token theft, MITM on outbound HTTPS |
| App → Git Remote | MITM on SSH push, credential theft |
| SSO IdP → App (OIDC/SAML) | CSRF, assertion replay, token injection |
| Admin → Secrets | Env var leakage, crash dump exposure |

**Existing Strengths (no changes needed):**

- AES-256-GCM with unique IV per token for provider credential encryption
- Argon2id for local password hashing
- JWT revocation via `sessions` table (SHA-256 of token stored, not raw token)
- RBAC enforced at every API handler via `RequestContext`
- Parameterized SQL via `libpqxx` (no raw string interpolation)
- Non-root container user (`dns-orchestrator` system account)
- Per-zone deployment mutex preventing concurrent pushes
- Provider isolation: internal-view records never sent to external providers

---

## 2. Findings and Decisions

### C-1 — API Key Hashing (SEC-01)

**Severity:** Critical  
**Component:** [`CryptoService`](../../include/security/CryptoService.hpp), [`ApiKeyRepository`](../../include/dal/ApiKeyRepository.hpp)

**Finding:**  
The architecture specifies SHA-256 for hashing API keys stored in the `api_keys` table. SHA-256 is a general-purpose fast hash designed for throughput, not password/key storage. An attacker who dumps the `api_keys` table could attempt offline brute-force at billions of hashes per second on commodity hardware.

**Mitigating Factor:**  
API keys will be generated as cryptographically random tokens (minimum 32 bytes / 256 bits of entropy). At this entropy level, brute-force is computationally infeasible regardless of hash speed.

**Decision:**  
Upgrade to **SHA-512** (available via OpenSSL `EVP_sha512()` — zero new dependencies). SHA-512 provides a larger output space and is marginally slower than SHA-256, providing defense-in-depth without the latency cost of Argon2id (which is inappropriate for per-request API key validation).

**Implementation Notes:**
- `CryptoService::hashApiKey(const std::string& raw_key)` → returns hex-encoded SHA-512 digest
- `ApiKeyRepository` uses this method on both create and lookup
- Schema comment updated: `key_hash TEXT NOT NULL UNIQUE -- SHA-512 of raw key`
- API key generation: use `RAND_bytes()` (OpenSSL) to generate 32 random bytes, base64url-encode → 43-character key
- Minimum enforced key entropy: 256 bits

---

### C-2 — OIDC CSRF / Replay (SEC-06)

**Severity:** Critical  
**Component:** [`AuthService`](../../include/security/AuthService.hpp), [`AuthRoutes`](../../include/api/routes/AuthRoutes.hpp)

**Finding:**  
The OIDC Authorization Code Flow with PKCE is specified, but the architecture does not document:
1. **`state` parameter validation** — without this, an attacker can perform a CSRF attack on `/auth/oidc/callback`, injecting their own authorization code and hijacking the victim's session
2. **`nonce` binding** — without a nonce bound to the ID token, a stolen ID token from one session can be replayed in another

**Decision:**  
Implement `state` and `nonce` via an **HMAC-signed, short-lived cookie** (no database required):

```
Cookie: oidc_state=<base64url(state||nonce||exp)>.<HMAC-SHA256(payload, DNS_JWT_SECRET)>
SameSite=Lax; HttpOnly; Secure; Max-Age=600
```

**Flow:**
1. `GET /auth/oidc/authorize`:
   - Generate `state` = 16 random bytes (base64url)
   - Generate `nonce` = 16 random bytes (base64url)
   - Set signed cookie containing `state`, `nonce`, `exp = now + 600s`
   - Include `state` and `nonce` in the redirect to IdP
2. `GET /auth/oidc/callback?code=...&state=...`:
   - Read and verify signed cookie (HMAC check + expiry check)
   - Verify `state` in query param matches `state` in cookie
   - Exchange code for ID token
   - Verify `nonce` claim in ID token matches `nonce` from cookie
   - Clear the cookie
   - Issue JWT session

**Implementation Notes:**
- Cookie signing uses `HMAC-SHA256` with `DNS_JWT_SECRET` (reuses existing secret)
- Cookie is `HttpOnly` + `Secure` + `SameSite=Lax`
- If cookie is absent, expired, or HMAC invalid → return `400 Bad Request`
- If `state` mismatch → return `400 Bad Request` (log as security event)
- If `nonce` mismatch → return `400 Bad Request` (log as security event)

---

### C-3 — SAML Assertion Replay (SEC-07)

**Severity:** Critical  
**Component:** [`AuthService`](../../include/security/AuthService.hpp), [`AuthRoutes`](../../include/api/routes/AuthRoutes.hpp)

**Finding:**  
The SAML ACS endpoint (`POST /auth/saml/acs`) has no documented mechanism to prevent assertion replay. A captured SAML assertion (e.g., via network interception or XSS) can be replayed within its `NotOnOrAfter` validity window to obtain a new session.

**Decision:**  
Implement an **in-memory assertion ID cache** with TTL-based eviction:

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
  void evictExpired();  // called on each insert
};
```

**Implementation Notes:**
- Cache is process-local (in-memory); acceptable for single-instance deployments
- For multi-instance deployments: document that a shared cache (Redis) is required; add a note to deployment docs
- `evictExpired()` removes entries where `not_on_or_after < now()` on every insert (amortized O(n) but bounded by assertion window size)
- If `assertion_id` already in cache → return `400 Bad Request`, log as security event
- Cache is owned by `AuthService` singleton

---

### H-1 — Secret Management (SEC-02)

**Severity:** High  
**Component:** [`Config`](../../include/common/Config.hpp)

**Finding:**  
`DNS_MASTER_KEY` and `DNS_JWT_SECRET` are loaded exclusively from environment variables. Risks:
- `/proc/self/environ` readable by processes with same UID
- Crash dumps may capture env var memory
- Child processes (e.g., `entrypoint.sh` subshells) inherit all env vars

**Decision:**  
Support **file-based secret loading** as an alternative. Env var takes precedence; file path is the production-recommended pattern (compatible with Docker secrets at `/run/secrets/` and Kubernetes secret volume mounts).

**Loading Logic (for each secret):**
```
1. If DNS_MASTER_KEY is set → use it
2. Else if DNS_MASTER_KEY_FILE is set → read file, trim whitespace, use contents
3. Else → fatal startup error: "DNS_MASTER_KEY or DNS_MASTER_KEY_FILE must be set"
```

**Security Properties of File-Based Loading:**
- File should be mode `0400` (owner read-only)
- Contents read once at startup into a `std::string`, then the file descriptor is closed
- After loading into `CryptoService`, the raw string should be zeroed (`OPENSSL_cleanse()`)
- File path itself is not sensitive and may remain in env

**Applies to:**
- `DNS_MASTER_KEY` / `DNS_MASTER_KEY_FILE`
- `DNS_JWT_SECRET` / `DNS_JWT_SECRET_FILE`

---

### H-2 — TLS Termination (SEC-08)

**Severity:** High  
**Component:** Deployment model, [`ApiServer`](../../include/api/ApiServer.hpp)

**Finding:**  
The Crow HTTP server listens on plain HTTP (`EXPOSE 8080`). Without TLS, all traffic — including JWT bearer tokens, API keys, and DNS record data — is transmitted in cleartext. The architecture assumes a reverse proxy handles TLS, but this is not documented as a requirement.

**Decision:**  
- **Current:** Reverse proxy handles TLS termination. This is a **hard deployment requirement**.
- **Future:** Native TLS support via Crow SSL bindings. Stub env vars now so the interface is stable.

**Deployment Requirement:**  
The application MUST be deployed behind a TLS-terminating reverse proxy (nginx, Caddy, Traefik, or equivalent). Direct exposure of port 8080 to untrusted networks is a security violation.

**Stubbed Future Env Vars (not implemented yet):**
- `DNS_TLS_CERT_FILE` — path to PEM certificate chain
- `DNS_TLS_KEY_FILE` — path to PEM private key

When both are set, a future implementation will configure Crow's SSL context instead of plain HTTP.

---

### H-3 — Audit Log Retention (SEC-04 + SEC-05)

**Severity:** High  
**Component:** [`AuditRepository`](../../include/dal/AuditRepository.hpp), [`AuditRoutes`](../../include/api/routes/AuditRoutes.hpp)

**Finding:**  
The audit log is insert-only with no purge mechanism. In a busy environment (frequent deployments, many users), the `audit_log` table will grow indefinitely, eventually causing storage exhaustion and query performance degradation.

A pure append-only enforcement (RLS/trigger blocking DELETE) would prevent any cleanup, creating an operational problem.

**Decision:**  
Balance tamper-prevention with operational manageability:

1. **Retention Policy:** `DNS_AUDIT_RETENTION_DAYS` (default: `365`) — configures the minimum age of records eligible for purge
2. **Privileged Purge Endpoint:** `DELETE /api/v1/audit/purge` (admin role only) — deletes records older than the retention window; returns count of deleted rows
3. **SIEM Export Endpoint:** `GET /api/v1/audit/export` (admin role only) — streams all audit records as NDJSON (`application/x-ndjson`) for ingestion by external SIEM before purge
4. **PostgreSQL Least-Privilege:** The application DB user (`dns_app`) does NOT have `DELETE` privilege on `audit_log`. A separate `dns_audit_admin` role is used exclusively for the purge operation (see SEC-13).
5. **SIEM Recommendation:** Document that production deployments should configure a SIEM (Splunk, Elastic, Datadog, etc.) to consume the export endpoint on a schedule before purging.

**Purge Endpoint Behavior:**
```
DELETE /api/v1/audit/purge
→ Deletes WHERE timestamp < NOW() - INTERVAL 'DNS_AUDIT_RETENTION_DAYS days'
→ Response: {"deleted": 1234, "oldest_remaining": "2025-02-26T00:00:00Z"}
```

**Export Endpoint Behavior:**
```
GET /api/v1/audit/export?from=2025-01-01&to=2025-12-31
→ Content-Type: application/x-ndjson
→ Streams one JSON object per line, one audit record per line
→ Supports ?from= and ?to= query params (ISO 8601)
```

---

### M-1 — JWT Algorithm Abstraction (SEC-03)

**Severity:** Medium  
**Component:** [`AuthService`](../../include/security/AuthService.hpp)

**Finding:**  
HS256 is hardcoded throughout the JWT signing/verification logic. Upgrading to RS256 or ES256 (asymmetric signing) in the future would require changes at every JWT call site.

**Decision:**  
Introduce a `IJwtSigner` interface so the signing strategy is swappable:

```cpp
// security/IJwtSigner.hpp
class IJwtSigner {
public:
  virtual ~IJwtSigner() = default;
  virtual std::string sign(const nlohmann::json& payload) const = 0;
  virtual nlohmann::json verify(const std::string& token)  const = 0;
  // throws AuthenticationError on invalid/expired token
};

// Concrete implementations:
// security/HmacJwtSigner.hpp   — HS256 (current)
// security/RsaJwtSigner.hpp    — RS256 (future)
// security/EcJwtSigner.hpp     — ES256 (future)
```

**Configuration:**
- `DNS_JWT_ALGORITHM` env var (default: `HS256`)
- `AuthService` constructs the appropriate `IJwtSigner` at startup via a factory
- `HS256` requires `DNS_JWT_SECRET` (or `DNS_JWT_SECRET_FILE`)
- `RS256`/`ES256` (future) will require `DNS_JWT_PRIVATE_KEY_FILE` + `DNS_JWT_PUBLIC_KEY_FILE`

---

### M-2 — Security Response Headers (SEC-12)

**Severity:** Medium  
**Component:** [`ApiServer`](../../include/api/ApiServer.hpp)

**Finding:**  
No HTTP security headers are set on responses. The Web GUI served by the API is vulnerable to:
- **Clickjacking** (missing `X-Frame-Options`)
- **MIME sniffing** (missing `X-Content-Type-Options`)
- **Information leakage** via `Referer` header (missing `Referrer-Policy`)
- **XSS** via inline scripts (missing `Content-Security-Policy`)

**Decision:**  
Add a Crow response middleware (applied to all routes) that injects:

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Content-Security-Policy: default-src 'self'
```

**Implementation Notes:**
- Implemented as a Crow `after_handle()` middleware method or equivalent post-processing hook in `ApiServer`
- `Content-Security-Policy` starts restrictive (`default-src 'self'`); can be relaxed for specific GUI asset needs
- `X-Frame-Options: DENY` prevents the app from being embedded in iframes (clickjacking)
- Do NOT set `Server:` header (remove Crow's default server identification header)

---

### M-3 — Input Size Limits (SEC-11)

**Severity:** Medium  
**Component:** [`ApiServer`](../../include/api/ApiServer.hpp), all route handlers

**Finding:**  
No maximum sizes are defined for HTTP request bodies or individual field values. A malicious client could send oversized payloads to exhaust memory or trigger pathological behavior in JSON parsing.

**Decision:**  
Define explicit limits enforced at two levels:

**Level 1 — HTTP Layer (Crow config):**
- Maximum request body size: **64 KB** (sufficient for any valid DNS API request)
- Requests exceeding this limit → `413 Payload Too Large`

**Level 2 — Application Layer (route handlers):**

| Field | Max Length |
|-------|-----------|
| Zone name | 253 characters (DNS spec limit) |
| Record name | 253 characters |
| Record value / template | 4096 characters |
| Variable name | 64 characters (already specified) |
| Variable value | 4096 characters |
| Provider name | 128 characters |
| Username | 128 characters |
| Password (input) | 1024 characters |
| API key description | 512 characters |
| Group name | 128 characters |
| Audit query `identity` filter | 128 characters |

**SQL Injection Prevention:**  
All SQL uses `libpqxx` parameterized queries (`pqxx::work::exec_params()`). No raw string interpolation of user input into SQL. This is already the design intent — document it explicitly in the architecture as a non-negotiable constraint.

---

### M-4 — Git SSH Host Verification (SEC-09)

**Severity:** Medium  
**Component:** [`GitOpsMirror`](../../include/gitops/GitOpsMirror.hpp)

**Finding:**  
`libgit2` will connect to any SSH host without fingerprint verification unless explicitly configured. A MITM attacker on the network path between the app and the Git remote could intercept pushes containing fully-expanded DNS zone data (including internal IP addresses).

**Decision:**  
- **Current:** Document the requirement; add env var stub for future implementation
- **Future:** Implement `libgit2` `git_remote_callbacks` with a `certificate_check` callback that validates against a known_hosts file

**Deployment Documentation Requirement:**
- The SSH deploy key MUST be scoped to a single repository (GitHub/GitLab deploy key, not a user key)
- The deploy key SHOULD have write-only access (push only, no clone of other repos)
- The Git remote SHOULD be on an internal network or accessed via a VPN if possible

**Stubbed Env Var:**
- `DNS_GIT_KNOWN_HOSTS_FILE` — path to a known_hosts file for SSH host verification (optional; when set in a future implementation, connections to unverified hosts will be rejected)

---

### L-1 — Rate Limiting (SEC-10)

**Severity:** Low  
**Component:** Deployment model (not application code)

**Finding:**  
No brute-force protection on `/auth/local/login` or API key validation. An attacker can make unlimited authentication attempts.

**Decision:**  
Delegate to the reverse proxy. The application will NOT implement in-process rate limiting.

**Deployment Requirement:**  
The reverse proxy MUST implement rate limiting on authentication endpoints. Reference configurations:

**nginx:**
```nginx
limit_req_zone $binary_remote_addr zone=auth:10m rate=5r/m;
location /api/v1/auth/local/login {
  limit_req zone=auth burst=3 nodelay;
  proxy_pass http://dns-orchestrator:8080;
}
```

**Caddy:**
```caddy
rate_limit /api/v1/auth/local/login 5r/m
```

**Traefik:**
```yaml
middlewares:
  auth-ratelimit:
    rateLimit:
      average: 5
      period: 1m
      burst: 3
```

---

### L-2 — PostgreSQL Least Privilege (SEC-13)

**Severity:** Low  
**Component:** Deployment model, database schema

**Finding:**  
The architecture uses a single `DNS_DB_URL` for all database operations. This means the application user has full DML access to all tables, including the ability to delete audit log records — undermining tamper-evidence.

**Decision:**  
Define two PostgreSQL roles:

**Role 1: `dns_app` (application runtime user)**
```sql
GRANT CONNECT ON DATABASE dns_orchestrator TO dns_app;
GRANT USAGE ON SCHEMA public TO dns_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO dns_app;
REVOKE DELETE ON audit_log FROM dns_app;  -- cannot delete audit records
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO dns_app;
```

**Role 2: `dns_audit_admin` (used only for audit purge)**
```sql
GRANT CONNECT ON DATABASE dns_orchestrator TO dns_audit_admin;
GRANT USAGE ON SCHEMA public TO dns_audit_admin;
GRANT SELECT, DELETE ON audit_log TO dns_audit_admin;  -- purge only
```

**Configuration:**
- `DNS_DB_URL` — connection string for `dns_app` (used for all normal operations)
- `DNS_AUDIT_DB_URL` — connection string for `dns_audit_admin` (used only by `DELETE /api/v1/audit/purge`)

The `AuditRepository` uses `DNS_DB_URL` for inserts and reads, and `DNS_AUDIT_DB_URL` for the purge operation.

---

## 3. New Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DNS_MASTER_KEY_FILE` | No | — | Path to file containing 32-byte hex master key; used if `DNS_MASTER_KEY` is unset |
| `DNS_JWT_SECRET_FILE` | No | — | Path to file containing JWT secret; used if `DNS_JWT_SECRET` is unset |
| `DNS_JWT_ALGORITHM` | No | `HS256` | JWT signing algorithm (`HS256` now; `RS256`/`ES256` in future) |
| `DNS_AUDIT_RETENTION_DAYS` | No | `365` | Minimum age in days for audit records eligible for purge |
| `DNS_AUDIT_DB_URL` | No | — | PostgreSQL connection string for `dns_audit_admin` role (required if audit purge endpoint is used) |
| `DNS_GIT_KNOWN_HOSTS_FILE` | No | — | Path to known_hosts file for SSH host verification (future implementation) |
| `DNS_TLS_CERT_FILE` | No | — | Path to PEM TLS certificate chain (future native TLS support) |
| `DNS_TLS_KEY_FILE` | No | — | Path to PEM TLS private key (future native TLS support) |

---

## 4. New API Endpoints

| Method | Path | Role | Description |
|--------|------|------|-------------|
| `DELETE` | `/api/v1/audit/purge` | admin | Purge audit entries older than `DNS_AUDIT_RETENTION_DAYS`; uses `dns_audit_admin` DB role |
| `GET` | `/api/v1/audit/export` | admin | Stream audit log as NDJSON (`application/x-ndjson`); supports `?from=` and `?to=` ISO 8601 params |

---

## 5. Implementation Checklist

| ID | Item | Severity | Status |
|----|------|----------|--------|
| SEC-01 | Upgrade API key hashing: SHA-256 → SHA-512 in `CryptoService` + `ApiKeyRepository` | Critical | Pending |
| SEC-02 | File-based secret loading: `DNS_MASTER_KEY_FILE`, `DNS_JWT_SECRET_FILE` in `Config` | High | Pending |
| SEC-03 | `IJwtSigner` interface + `HmacJwtSigner` (HS256); `DNS_JWT_ALGORITHM` env var | Medium | Pending |
| SEC-04 | Audit retention: `DNS_AUDIT_RETENTION_DAYS`; `DELETE /api/v1/audit/purge` endpoint | High | Pending |
| SEC-05 | SIEM export: `GET /api/v1/audit/export` NDJSON streaming endpoint | High | Pending |
| SEC-06 | OIDC hardening: HMAC-signed state+nonce cookie; validate on callback | Critical | Pending |
| SEC-07 | SAML hardening: `SamlReplayCache` in-memory assertion ID cache with TTL eviction | Critical | Pending |
| SEC-08 | TLS documentation: reverse proxy requirement; stub `DNS_TLS_CERT_FILE`/`DNS_TLS_KEY_FILE` | High | Pending |
| SEC-09 | Git security documentation: deploy key scope; stub `DNS_GIT_KNOWN_HOSTS_FILE` | Medium | Pending |
| SEC-10 | Rate limiting documentation: nginx/Caddy/Traefik examples in deployment docs | Low | Pending |
| SEC-11 | Input size limits: 64KB body limit in Crow; field-level limits in route handlers | Medium | Pending |
| SEC-12 | Security response headers middleware in `ApiServer` | Medium | Pending |
| SEC-13 | PostgreSQL least-privilege: `dns_app` + `dns_audit_admin` roles; `DNS_AUDIT_DB_URL` | Low | Pending |
| SEC-14 | Update `ARCHITECTURE.md` with all decisions from this review | — | Pending |
