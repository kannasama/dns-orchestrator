# Provider Configuration: Database-Driven Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Move all DNS provider configuration from environment variables / docker-compose services into the database `providers` table, making the system truly multi-provider.

**Architecture:** The current `providers` table stores `api_endpoint` and `encrypted_token` per provider. This is sufficient for PowerDNS (endpoint + API key) and DigitalOcean (endpoint + bearer token), but Cloudflare requires an additional `account_id` for zone-scoped operations. Rather than adding provider-specific columns, we add a single `encrypted_config` JSONB column that stores provider-specific parameters (encrypted at rest). The `powerdns` container is removed from `docker-compose.yml` since providers are external services configured through the application. The `ProviderFactory` and provider constructors are updated to accept a config map.

**Tech Stack:** C++17, PostgreSQL 16, libpqxx, nlohmann/json, CryptoService (AES-256-GCM), Crow HTTP, Vue 3 + PrimeVue

---

## Context for Implementers

### Current State

- **`docker-compose.yml`** lines 18-28: Contains a `powerdns` service with `PDNS_AUTH_API_KEY` env var. This couples the deployment to a specific PowerDNS instance.
- **`.env.example`** lines 12-13: Contains `PDNS_API_KEY` and `PDNS_HTTP_PORT` variables.
- **`providers` table** (`scripts/db/v001/001_initial_schema.sql` lines 16-24): Has columns `api_endpoint TEXT` and `encrypted_token TEXT`. No provider-specific config storage.
- **`ProviderFactory::create()`** (`src/providers/ProviderFactory.cpp`): Takes `(sType, sApiEndpoint, sDecryptedToken)` — no way to pass extra config.
- **Provider constructors** (`PowerDnsProvider`, `CloudflareProvider`, `DigitalOceanProvider`): All take `(sApiEndpoint, sToken)`.
- **`ProviderRepository`** (`src/dal/ProviderRepository.cpp`): CRUD with `(name, type, api_endpoint, encrypted_token)`.
- **`ProviderRow`** (`include/dal/ProviderRepository.hpp` lines 22-30): Has `sApiEndpoint` and `sDecryptedToken`.
- **UI `ProvidersView.vue`**: Form has `name`, `type`, `api_endpoint`, `token` fields.
- **UI `types/index.ts`**: `Provider`, `ProviderCreate`, `ProviderUpdate` interfaces.
- **`openapi.yaml`**: Provider schemas with `api_endpoint` and `token`.

### Provider-Specific Required Parameters

| Provider | `api_endpoint` | `token` (API key) | Additional Config |
|----------|---------------|-------------------|-------------------|
| **PowerDNS** | `http://pdns:8081` | API key (`X-API-Key` header) | `server_id` (default: `localhost`) |
| **Cloudflare** | `https://api.cloudflare.com/client/v4` | API token (Bearer) | `account_id` (required for zone listing) |
| **DigitalOcean** | `https://api.digitalocean.com/v2` | API token (Bearer) | _(none currently)_ |

### Design Decision: `encrypted_config` JSONB Column

Instead of adding provider-specific columns, we add a single `encrypted_config TEXT` column that stores a JSON object encrypted with `CryptoService`. This keeps the schema extensible for future providers without migrations.

**Stored as:** `CryptoService::encrypt(json_string)` → ciphertext in `encrypted_config`
**Read as:** `CryptoService::decrypt(encrypted_config)` → JSON string → `nlohmann::json`

Example stored configs (before encryption):
- PowerDNS: `{"server_id": "localhost"}`
- Cloudflare: `{"account_id": "abc123"}`
- DigitalOcean: `{}`

The `api_endpoint` and `encrypted_token` columns remain as top-level columns since every provider needs them.

---

## Task 1: Schema Migration — Add `encrypted_config` Column

**Files:**
- Create: `scripts/db/v002/001_add_provider_config.sql`

**Step 1: Write the migration SQL**

```sql
-- 001_add_provider_config.sql
-- Adds encrypted_config column for provider-specific parameters.

ALTER TABLE providers ADD COLUMN encrypted_config TEXT NOT NULL DEFAULT '';
```

The default empty string means existing rows get a valid (empty) value. The application treats empty string as `{}` (empty JSON object).

**Step 2: Verify migration applies cleanly**

Run: `cd /home/mjhill/Projects/Git/dns-orchestrator && docker compose up -d db && docker compose run --rm app ./meridian-dns --migrate`
Expected: `Migrations complete. Schema version: 2`

**Step 3: Commit**

```bash
git add scripts/db/v002/001_add_provider_config.sql
git commit -m "feat(schema): add encrypted_config column to providers table"
```

---

## Task 2: Update `ProviderRow` and `ProviderRepository` for Config Column

**Files:**
- Modify: `include/dal/ProviderRepository.hpp` (lines 22-30, 41-43, 52-54)
- Modify: `src/dal/ProviderRepository.cpp` (lines 17-36, 38-54, 56-69, 71-101, 115-127)
- Test: `tests/integration/test_provider_repository.cpp`

**Step 1: Write the failing test**

Add to `tests/integration/test_provider_repository.cpp`:

```cpp
TEST_F(ProviderRepositoryTest, CreateAndFindByIdWithConfig) {
  nlohmann::json jConfig = {{"server_id", "localhost"}};
  int64_t iId = _prRepo->create("pdns-with-config", "powerdns",
                                "http://localhost:8081", "secret-key",
                                jConfig);
  EXPECT_GT(iId, 0);

  auto oRow = _prRepo->findById(iId);
  ASSERT_TRUE(oRow.has_value());
  EXPECT_EQ(oRow->sName, "pdns-with-config");
  EXPECT_EQ(oRow->jConfig["server_id"], "localhost");
}

TEST_F(ProviderRepositoryTest, CreateWithEmptyConfig) {
  int64_t iId = _prRepo->create("pdns-no-config", "powerdns",
                                "http://localhost:8081", "secret-key",
                                nlohmann::json::object());
  auto oRow = _prRepo->findById(iId);
  ASSERT_TRUE(oRow.has_value());
  EXPECT_TRUE(oRow->jConfig.is_object());
  EXPECT_TRUE(oRow->jConfig.empty());
}

TEST_F(ProviderRepositoryTest, UpdateWithConfig) {
  int64_t iId = _prRepo->create("config-update", "powerdns",
                                "http://localhost:8081", "key",
                                nlohmann::json{{"server_id", "old"}});

  _prRepo->update(iId, "config-update", "http://localhost:8081",
                  std::nullopt,
                  nlohmann::json{{"server_id", "new-server"}});

  auto oRow = _prRepo->findById(iId);
  ASSERT_TRUE(oRow.has_value());
  EXPECT_EQ(oRow->jConfig["server_id"], "new-server");
}
```

Add `#include <nlohmann/json.hpp>` to the test file's includes.

**Step 2: Run test to verify it fails**

Run: `cd build && cmake --build . --target test_provider_repository && ctest -R test_provider_repository -V`
Expected: FAIL — compilation error (no `jConfig` member, wrong `create()` signature)

**Step 3: Update `ProviderRow` struct**

In `include/dal/ProviderRepository.hpp`, add `#include <nlohmann/json.hpp>` and add to `ProviderRow`:

```cpp
struct ProviderRow {
  int64_t iId = 0;
  std::string sName;
  std::string sType;
  std::string sApiEndpoint;
  std::string sDecryptedToken;
  nlohmann::json jConfig = nlohmann::json::object();  // provider-specific config
  std::chrono::system_clock::time_point tpCreatedAt;
  std::chrono::system_clock::time_point tpUpdatedAt;
};
```

**Step 4: Update `ProviderRepository` method signatures**

In `include/dal/ProviderRepository.hpp`, update:

```cpp
int64_t create(const std::string& sName, const std::string& sType,
               const std::string& sApiEndpoint,
               const std::string& sPlaintextToken,
               const nlohmann::json& jConfig = nlohmann::json::object());

void update(int64_t iId, const std::string& sName,
            const std::string& sApiEndpoint,
            const std::optional<std::string>& oPlaintextToken,
            const std::optional<nlohmann::json>& oConfig = std::nullopt);
```

**Step 5: Update `ProviderRepository` implementation**

In `src/dal/ProviderRepository.cpp`:

- `create()`: Encrypt `jConfig.dump()` via `_csService.encrypt()`, INSERT into `encrypted_config`
- `listAll()` and `findById()`: SELECT `encrypted_config`, decrypt and parse in `mapRow()`
- `update()`: If `oConfig.has_value()`, encrypt and UPDATE `encrypted_config`
- `mapRow()`: Decrypt `encrypted_config`, parse JSON. If empty string, use `json::object()`.

**Step 6: Run tests to verify they pass**

Run: `cd build && cmake --build . --target test_provider_repository && ctest -R test_provider_repository -V`
Expected: All tests PASS (existing tests still pass with default `jConfig` parameter)

**Step 7: Commit**

```bash
git add include/dal/ProviderRepository.hpp src/dal/ProviderRepository.cpp tests/integration/test_provider_repository.cpp
git commit -m "feat(dal): add encrypted_config to ProviderRow and ProviderRepository"
```

---

## Task 3: Update `ProviderFactory` and Provider Constructors

**Files:**
- Modify: `include/providers/ProviderFactory.hpp`
- Modify: `src/providers/ProviderFactory.cpp`
- Modify: `include/providers/PowerDnsProvider.hpp` (line 19)
- Modify: `src/providers/PowerDnsProvider.cpp` (constructor)
- Modify: `include/providers/CloudflareProvider.hpp` (line 13)
- Modify: `src/providers/CloudflareProvider.cpp` (constructor)
- Modify: `include/providers/DigitalOceanProvider.hpp` (line 13)
- Modify: `src/providers/DigitalOceanProvider.cpp` (constructor)
- Test: `tests/unit/test_provider_factory.cpp`

**Step 1: Write the failing test**

Update `tests/unit/test_provider_factory.cpp`:

```cpp
#include <nlohmann/json.hpp>

TEST(ProviderFactoryTest, CreatesPowerDnsProviderWithConfig) {
  nlohmann::json jConfig = {{"server_id", "localhost"}};
  auto upProvider = ProviderFactory::create("powerdns", "http://localhost:8081",
                                            "test-key", jConfig);
  ASSERT_NE(upProvider, nullptr);
  EXPECT_EQ(upProvider->name(), "powerdns");
}

TEST(ProviderFactoryTest, CreatesPowerDnsProviderWithEmptyConfig) {
  auto upProvider = ProviderFactory::create("powerdns", "http://localhost:8081",
                                            "test-key", nlohmann::json::object());
  ASSERT_NE(upProvider, nullptr);
  EXPECT_EQ(upProvider->name(), "powerdns");
}
```

**Step 2: Run test to verify it fails**

Run: `cd build && cmake --build . --target test_provider_factory && ctest -R test_provider_factory -V`
Expected: FAIL — compilation error (wrong `create()` signature)

**Step 3: Update `ProviderFactory::create()` signature**

In `include/providers/ProviderFactory.hpp`:

```cpp
#include <nlohmann/json.hpp>

static std::unique_ptr<IProvider> create(const std::string& sType,
                                         const std::string& sApiEndpoint,
                                         const std::string& sDecryptedToken,
                                         const nlohmann::json& jConfig = nlohmann::json::object());
```

In `src/providers/ProviderFactory.cpp`, update the implementation to pass `jConfig` to constructors.

**Step 4: Update provider constructors to accept config**

All three providers get a third constructor parameter:

```cpp
// PowerDnsProvider
PowerDnsProvider(std::string sApiEndpoint, std::string sToken,
                 nlohmann::json jConfig = nlohmann::json::object());
// Store _jConfig member, extract server_id with default "localhost"

// CloudflareProvider
CloudflareProvider(std::string sApiEndpoint, std::string sToken,
                   nlohmann::json jConfig = nlohmann::json::object());
// Store _jConfig member, extract account_id

// DigitalOceanProvider
DigitalOceanProvider(std::string sApiEndpoint, std::string sToken,
                     nlohmann::json jConfig = nlohmann::json::object());
// Store _jConfig member (no extra fields currently)
```

Each provider stores `_jConfig` as a member and extracts its specific fields in the constructor. For PowerDNS, `_sServerId` defaults to `"localhost"` if not in config.

**Step 5: Update existing tests to use new signature**

Update `tests/unit/test_provider_factory.cpp` — existing tests that use the 3-arg `create()` still compile because `jConfig` has a default value.

**Step 6: Run all tests to verify they pass**

Run: `cd build && cmake --build . && ctest -V`
Expected: All tests PASS

**Step 7: Commit**

```bash
git add include/providers/ProviderFactory.hpp src/providers/ProviderFactory.cpp \
        include/providers/PowerDnsProvider.hpp src/providers/PowerDnsProvider.cpp \
        include/providers/CloudflareProvider.hpp src/providers/CloudflareProvider.cpp \
        include/providers/DigitalOceanProvider.hpp src/providers/DigitalOceanProvider.cpp \
        tests/unit/test_provider_factory.cpp
git commit -m "feat(providers): add config parameter to ProviderFactory and provider constructors"
```

---

## Task 4: Update `DiffEngine` and `DeploymentEngine` to Pass Config

**Files:**
- Modify: `src/core/DiffEngine.cpp` (line ~177-178)
- Modify: `src/core/DeploymentEngine.cpp` (line ~132-133)

**Step 1: Update `ProviderFactory::create()` calls**

Both `DiffEngine` and `DeploymentEngine` call `ProviderFactory::create()` with data from `ProviderRow`. Update both call sites to pass `oProvider->jConfig`:

In `src/core/DiffEngine.cpp` (~line 177):
```cpp
auto upProvider = dns::providers::ProviderFactory::create(
    oProvider->sType, oProvider->sApiEndpoint, oProvider->sDecryptedToken,
    oProvider->jConfig);
```

In `src/core/DeploymentEngine.cpp` (~line 132):
```cpp
auto upProvider = dns::providers::ProviderFactory::create(
    oProvider->sType, oProvider->sApiEndpoint, oProvider->sDecryptedToken,
    oProvider->jConfig);
```

**Step 2: Run all tests**

Run: `cd build && cmake --build . && ctest -V`
Expected: All tests PASS

**Step 3: Commit**

```bash
git add src/core/DiffEngine.cpp src/core/DeploymentEngine.cpp
git commit -m "feat(core): pass provider config to ProviderFactory in DiffEngine and DeploymentEngine"
```

---

## Task 5: Update Provider API Routes for Config Field

**Files:**
- Modify: `src/api/routes/ProviderRoutes.cpp` (create and update handlers)
- Test: `tests/integration/test_crud_routes.cpp` (provider CRUD tests)

**Step 1: Read current ProviderRoutes implementation**

Read `src/api/routes/ProviderRoutes.cpp` to understand the current JSON parsing for create/update.

**Step 2: Update create handler**

In the POST handler, parse optional `config` field from request JSON:

```cpp
nlohmann::json jConfig = nlohmann::json::object();
if (jBody.contains("config") && jBody["config"].is_object()) {
  jConfig = jBody["config"];
}
auto iId = _prRepo.create(sName, sType, sApiEndpoint, sToken, jConfig);
```

**Step 3: Update GET response to include config**

In the GET (single) and LIST handlers, include `config` in the response JSON:

```cpp
jProvider["config"] = row.jConfig;
```

For the LIST endpoint, **do not** include `token` (already the case), but **do** include `config` since it contains non-secret metadata.

**Step 4: Update update handler**

In the PUT handler, parse optional `config` field:

```cpp
std::optional<nlohmann::json> oConfig;
if (jBody.contains("config") && jBody["config"].is_object()) {
  oConfig = jBody["config"];
}
_prRepo.update(iId, sName, sApiEndpoint, oToken, oConfig);
```

**Step 5: Run tests**

Run: `cd build && cmake --build . && ctest -V`
Expected: All tests PASS

**Step 6: Commit**

```bash
git add src/api/routes/ProviderRoutes.cpp
git commit -m "feat(api): support config field in provider CRUD endpoints"
```

---

## Task 6: Update OpenAPI Spec

**Files:**
- Modify: `docs/openapi.yaml` (Provider, ProviderCreate, ProviderUpdate schemas)

**Step 1: Update Provider schema**

Add `config` field to the `Provider` schema:

```yaml
    Provider:
      type: object
      properties:
        id:
          type: integer
        name:
          type: string
        type:
          type: string
          enum: [powerdns, cloudflare, digitalocean]
        api_endpoint:
          type: string
        token:
          type: string
          description: Only returned on GET /providers/{id}
        config:
          type: object
          description: Provider-specific configuration parameters
          additionalProperties: true
        created_at:
          type: number
        updated_at:
          type: number
```

**Step 2: Update ProviderCreate schema**

```yaml
    ProviderCreate:
      type: object
      required: [name, type, api_endpoint, token]
      properties:
        name:
          type: string
        type:
          type: string
          enum: [powerdns, cloudflare, digitalocean]
        api_endpoint:
          type: string
        token:
          type: string
        config:
          type: object
          description: Provider-specific configuration (e.g., server_id for PowerDNS, account_id for Cloudflare)
          additionalProperties: true
```

**Step 3: Update ProviderUpdate schema**

```yaml
    ProviderUpdate:
      type: object
      required: [name, api_endpoint]
      properties:
        name:
          type: string
        api_endpoint:
          type: string
        token:
          type: string
        config:
          type: object
          description: Provider-specific configuration. Replaces existing config entirely when provided.
          additionalProperties: true
```

**Step 4: Commit**

```bash
git add docs/openapi.yaml
git commit -m "docs(openapi): add config field to Provider schemas"
```

---

## Task 7: Update UI Types and Provider Form

**Files:**
- Modify: `ui/src/types/index.ts` (Provider, ProviderCreate, ProviderUpdate)
- Modify: `ui/src/views/ProvidersView.vue` (form fields)

**Step 1: Update TypeScript types**

In `ui/src/types/index.ts`:

```typescript
export interface Provider {
  id: number
  name: string
  type: string
  api_endpoint: string
  token?: string
  config: Record<string, string>
  created_at: number
  updated_at: number
}

export interface ProviderCreate {
  name: string
  type: string
  api_endpoint: string
  token: string
  config?: Record<string, string>
}

export interface ProviderUpdate {
  name: string
  api_endpoint: string
  token?: string
  config?: Record<string, string>
}
```

**Step 2: Update ProvidersView.vue form**

Add provider-specific config fields that appear/disappear based on the selected `type`:

- **PowerDNS**: Show `Server ID` field (default: `localhost`)
- **Cloudflare**: Show `Account ID` field (required)
- **DigitalOcean**: No extra fields

The form's `config` object is built from these fields on submit. Example template additions:

```vue
<div class="field" v-if="form.type === 'powerdns'">
  <label for="prov-server-id">Server ID</label>
  <InputText id="prov-server-id" v-model="form.server_id" class="w-full"
             placeholder="localhost" />
</div>
<div class="field" v-if="form.type === 'cloudflare'">
  <label for="prov-account-id">Account ID</label>
  <InputText id="prov-account-id" v-model="form.account_id" class="w-full" />
</div>
```

On submit, build the `config` object:

```typescript
function buildConfig(): Record<string, string> {
  const config: Record<string, string> = {}
  if (form.value.type === 'powerdns' && form.value.server_id) {
    config.server_id = form.value.server_id
  }
  if (form.value.type === 'cloudflare' && form.value.account_id) {
    config.account_id = form.value.account_id
  }
  return config
}
```

On edit, populate form fields from `config`:

```typescript
async function openEdit(provider: Provider) {
  const full = await api.getProvider(provider.id)
  editingId.value = provider.id
  form.value = {
    name: full.name,
    type: full.type,
    api_endpoint: full.api_endpoint,
    token: '',
    server_id: full.config?.server_id ?? '',
    account_id: full.config?.account_id ?? '',
  }
  drawerVisible.value = true
}
```

**Step 3: Commit**

```bash
git add ui/src/types/index.ts ui/src/views/ProvidersView.vue
git commit -m "feat(ui): add provider-specific config fields to provider form"
```

---

## Task 8: Remove PowerDNS Container from Docker Compose

**Files:**
- Modify: `docker-compose.yml` (remove lines 18-28)
- Modify: `.env.example` (remove PDNS_API_KEY, PDNS_HTTP_PORT, PDNS_DNS_PORT)

**Step 1: Remove `powerdns` service from `docker-compose.yml`**

Remove the entire `powerdns:` service block (lines 18-28). The `app` service's `depends_on` already only references `db`, so no change needed there.

Result:

```yaml
services:
  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: meridian_dns
      POSTGRES_USER: dns
      POSTGRES_PASSWORD: ${DNS_DB_PASSWORD:-dns_dev_password}
    volumes:
      - pgdata:/var/lib/postgresql/data
    ports:
      - "${DNS_DB_PORT:-5432}:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U dns -d meridian_dns"]
      interval: 5s
      timeout: 3s
      retries: 5

  app:
    build: .
    depends_on:
      db:
        condition: service_healthy
    environment:
      DNS_DB_URL: postgresql://dns:${DNS_DB_PASSWORD:-dns_dev_password}@db:5432/meridian_dns
      DNS_MASTER_KEY: ${DNS_MASTER_KEY}
      DNS_JWT_SECRET: ${DNS_JWT_SECRET}
      DNS_HTTP_PORT: "8080"
      DNS_AUDIT_STDOUT: "true"
      DNS_LOG_LEVEL: "${DNS_LOG_LEVEL:-info}"
    ports:
      - "${DNS_HTTP_PORT:-8080}:8080"
    volumes:
      - gitrepo:/var/meridian-dns/repo

volumes:
  pgdata:
  gitrepo:
```

**Step 2: Clean up `.env.example`**

Remove PowerDNS-specific variables:

```
# Meridian DNS — Environment Variables
# Copy to .env and fill in values: cp .env.example .env

# Required secrets (generate with: openssl rand -hex 32)
DNS_MASTER_KEY=
DNS_JWT_SECRET=

# Database
DNS_DB_PASSWORD=dns_dev_password

# Web UI (path to built static files, empty = disabled)
# DNS_UI_DIR=/opt/meridian-dns/ui

# Optional overrides
# DNS_HTTP_PORT=8080
# DNS_DB_PORT=5432
# DNS_LOG_LEVEL=info
```

**Step 3: Commit**

```bash
git add docker-compose.yml .env.example
git commit -m "feat(docker): remove powerdns container, clean up env vars

Provider configuration is now managed through the database via the
Providers API. External PowerDNS, Cloudflare, and DigitalOcean instances
are configured through the web UI or API."
```

---

## Task 9: Update Documentation

**Files:**
- Modify: `docs/ARCHITECTURE.md` (§8 Configuration, §11 Dockerfile/Deployment)
- Modify: `README.md` (if it references PowerDNS container or PDNS env vars)

**Step 1: Search for PowerDNS/PDNS references in docs**

Run: `grep -rn "PDNS\|powerdns" docs/ README.md`

**Step 2: Update ARCHITECTURE.md §8**

Remove any `PDNS_*` environment variables from the configuration table. Add a note that provider configuration is stored in the database.

**Step 3: Update README.md**

Remove references to the PowerDNS container from the quick-start section. Update to explain that providers are configured through the web UI after initial setup.

**Step 4: Commit**

```bash
git add docs/ARCHITECTURE.md README.md
git commit -m "docs: update architecture and README for database-driven provider config"
```

---

## Summary of Changes

| Area | Change |
|------|--------|
| **Schema** | New `v002/001_add_provider_config.sql` — adds `encrypted_config TEXT` column |
| **DAL** | `ProviderRow` gains `jConfig`; `ProviderRepository` CRUD handles config |
| **Providers** | `ProviderFactory::create()` and all provider constructors accept `nlohmann::json jConfig` |
| **Core** | `DiffEngine` and `DeploymentEngine` pass `jConfig` to `ProviderFactory` |
| **API** | Provider routes accept/return `config` JSON object |
| **OpenAPI** | Provider schemas include `config` field |
| **UI** | Provider form shows type-specific config fields |
| **Docker** | `powerdns` service removed from `docker-compose.yml` |
| **Env** | `PDNS_*` variables removed from `.env.example` |
| **Docs** | Architecture and README updated |
