# Phase 10: Additional Providers — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement Cloudflare API v4 and DigitalOcean API v2 providers with full CRUD,
provider-specific features (Cloudflare proxy support), multi-provider deployment improvements,
and a provider-agnostic conformance test suite.

**Architecture:** Both providers follow the existing `IProvider` interface pattern established
by `PowerDnsProvider`. Each provider uses cpp-httplib for HTTP communication with the
provider's REST API. Cloudflare's proxy toggle (`proxied` flag) requires extending `DnsRecord`
with a provider-metadata field. Multi-provider deployment uses the existing views system
(zone → view → N providers) with per-provider diff/push execution. A conformance test suite
validates all providers implement the interface consistently using mock HTTP responses.

**Tech Stack:** C++20, cpp-httplib v0.18.7, nlohmann/json, Google Test/Mock, PostgreSQL (libpqxx)

---

## Table of Contents

1. [Provider-Specific Metadata (DnsRecord extension)](#task-1-provider-specific-metadata)
2. [Cloudflare Provider — Zone ID Resolution](#task-2-cloudflare-zone-id-resolution)
3. [Cloudflare Provider — testConnectivity + listRecords](#task-3-cloudflare-connectivity--list-records)
4. [Cloudflare Provider — createRecord + updateRecord + deleteRecord](#task-4-cloudflare-crud-operations)
5. [Cloudflare Proxy Support — IProvider + DiffEngine](#task-5-cloudflare-proxy-support)
6. [Cloudflare Proxy Support — UI](#task-6-cloudflare-proxy-support-ui)
7. [DigitalOcean Provider — testConnectivity + listRecords](#task-7-digitalocean-connectivity--list-records)
8. [DigitalOcean Provider — createRecord + updateRecord + deleteRecord](#task-8-digitalocean-crud-operations)
9. [Provider Conformance Test Suite](#task-9-provider-conformance-test-suite)
10. [Multi-Provider Deployment Improvements](#task-10-multi-provider-deployment-improvements)
11. [Documentation + CLAUDE.md Update](#task-11-documentation-update)

---

## Design Decisions

### Cloudflare API v4

Cloudflare's API uses zone IDs (not zone names) for all record operations. The flow is:

1. **Zone ID lookup:** `GET /client/v4/zones?name=example.com` → returns zone ID
2. **List records:** `GET /client/v4/zones/{zone_id}/dns_records` → paginated records
3. **Create record:** `POST /client/v4/zones/{zone_id}/dns_records` → single record
4. **Update record:** `PATCH /client/v4/zones/{zone_id}/dns_records/{record_id}` → single record
5. **Delete record:** `DELETE /client/v4/zones/{zone_id}/dns_records/{record_id}`

**Authentication:** Bearer token via `Authorization: Bearer {token}` header.

**Base URL:** `https://api.cloudflare.com` (configurable via `api_endpoint`).

**Provider config (`jConfig`):**
- No required fields — zone ID is resolved dynamically from zone name
- Optional `account_id` for multi-account setups (not used in API calls, for UI display)

**Proxy support:** Cloudflare has a `proxied` boolean on A/AAAA/CNAME records that routes
traffic through Cloudflare's CDN/WAF. This is a provider-specific feature that doesn't map
to standard DNS record fields.

**Record ID format:** Cloudflare returns a UUID `id` per record. We use this directly as
`sProviderRecordId` (no synthetic ID needed unlike PowerDNS).

### DigitalOcean API v2

DigitalOcean's API uses zone names directly:

1. **List records:** `GET /v2/domains/{domain}/records` → paginated records
2. **Create record:** `POST /v2/domains/{domain}/records` → single record
3. **Update record:** `PUT /v2/domains/{domain}/records/{record_id}` → single record
4. **Delete record:** `DELETE /v2/domains/{domain}/records/{record_id}`

**Authentication:** Bearer token via `Authorization: Bearer {token}` header.

**Base URL:** `https://api.digitalocean.com` (configurable via `api_endpoint`).

**Record ID format:** DigitalOcean returns a numeric `id`. Stored as string in
`sProviderRecordId`.

**DigitalOcean quirks:**
- Record names are relative to the zone (e.g., `www` not `www.example.com`)
- SOA records not returned by default
- `priority` is a top-level field (not embedded in data for MX/SRV)
- Pagination via `?page=N&per_page=200` (max 200)
- Record types: A, AAAA, CAA, CNAME, MX, NS, SRV, TXT

### Provider-Specific Metadata

To support Cloudflare's `proxied` flag without polluting the core `DnsRecord` type, we add
a `jProviderMeta` field (optional JSON) to `DnsRecord`. This field:

- Is populated by providers when listing records (e.g., `{"proxied": true}`)
- Is stored in the `records` table as a nullable `provider_meta JSONB` column
- Is passed through to providers on create/update so they can apply provider-specific settings
- Is ignored by DiffEngine when computing diffs (only name/type/value/ttl matter for equality)
- Is displayed in the UI when relevant (e.g., Cloudflare proxy toggle)

This is deliberately a JSON blob rather than typed fields — it keeps the interface generic
for future providers that may have their own specific settings.

### Multi-Provider Deployment

The existing system already supports zones deployed to multiple providers via views. Current
behavior:

1. `DiffEngine::fetchLiveRecords()` fetches from all providers and merges into one list
2. `DeploymentEngine::push()` applies the same diffs to all providers in the view

**Issues with current approach:**
- Merging records from multiple providers creates false diffs (records exist on provider A
  but show as "drift" because they don't exist on provider B)
- All providers receive identical operations, but different providers may have different
  existing state

**Solution — per-provider diff/push:**
- `DiffEngine::preview()` returns per-provider preview results (or a combined view with
  provider attribution)
- `DeploymentEngine::push()` computes a fresh diff per provider and applies only the
  relevant changes
- The UI shows which provider each diff applies to

This is a significant refactor of the deployment pipeline but is necessary for correct
multi-provider behavior.

### Per-Provider Diff Architecture

Refactor `DiffEngine::fetchLiveRecords()` to return a map of provider ID → records instead
of merging. Add `DiffEngine::previewPerProvider()` that returns a vector of
`ProviderPreviewResult` (one per provider). The existing `preview()` method is updated to
call `previewPerProvider()` and merge the results for backwards compatibility.

`DeploymentEngine::push()` is updated to iterate per-provider, computing a fresh diff for
each and applying only that provider's changes.

---

## Schema Changes

### Migration: `scripts/db/v004/001_add_provider_meta.sql`

```sql
-- 001_add_provider_meta.sql
-- Adds provider-specific metadata column to records table.

ALTER TABLE records ADD COLUMN provider_meta JSONB;
```

This column stores provider-specific settings per record (e.g., `{"proxied": true}` for
Cloudflare records). It is nullable — most records won't have provider metadata.

---

### Task 1: Provider-Specific Metadata

**Goal:** Extend `DnsRecord` with `jProviderMeta` field and persist it in the database.

**Files:**
- Modify: `include/common/Types.hpp:12-19` (add `jProviderMeta` field)
- Create: `scripts/db/v004/001_add_provider_meta.sql`
- Modify: `include/dal/RecordRepository.hpp` (add `jProviderMeta` to `RecordRow`)
- Modify: `src/dal/RecordRepository.cpp` (read/write `provider_meta` column)
- Test: `tests/unit/test_types.cpp` (new — verify default-constructed DnsRecord has null meta)

**Step 1: Write the migration**

Create `scripts/db/v004/001_add_provider_meta.sql`:

```sql
-- 001_add_provider_meta.sql
-- Adds provider-specific metadata column to records table.

ALTER TABLE records ADD COLUMN provider_meta JSONB;
```

**Step 2: Extend DnsRecord**

In `include/common/Types.hpp`, add to the `DnsRecord` struct after `iPriority`:

```cpp
struct DnsRecord {
  std::string sProviderRecordId;
  std::string sName;
  std::string sType;
  uint32_t uTtl = 300;
  std::string sValue;
  int iPriority = 0;
  nlohmann::json jProviderMeta;  // Provider-specific metadata (e.g., {"proxied": true})
};
```

Add `#include <nlohmann/json.hpp>` to the includes.

**Step 3: Extend RecordRow**

In `include/dal/RecordRepository.hpp`, add to `RecordRow`:

```cpp
nlohmann::json jProviderMeta;  // nullable JSONB from DB
```

**Step 4: Update RecordRepository**

In `src/dal/RecordRepository.cpp`:

- `create()` — add `provider_meta` to INSERT (pass `jProviderMeta.dump()` if not null,
  else SQL NULL)
- `listByZoneId()` — read `provider_meta` column in SELECT, parse JSON if not null
- `findById()` — same
- `upsertById()` — include `provider_meta` in UPSERT

**Step 5: Write failing test**

```cpp
// tests/unit/test_types.cpp
#include "common/Types.hpp"
#include <gtest/gtest.h>

TEST(DnsRecordTest, DefaultProviderMetaIsNull) {
  dns::common::DnsRecord dr;
  EXPECT_TRUE(dr.jProviderMeta.is_null());
}

TEST(DnsRecordTest, ProviderMetaStoresJson) {
  dns::common::DnsRecord dr;
  dr.jProviderMeta = {{"proxied", true}};
  EXPECT_TRUE(dr.jProviderMeta.value("proxied", false));
}
```

**Step 6: Run tests to verify they pass**

```bash
cmake --build build --parallel && build/tests/dns-tests --gtest_filter="DnsRecordTest*"
```

**Step 7: Commit**

```bash
git add include/common/Types.hpp include/dal/RecordRepository.hpp \
  src/dal/RecordRepository.cpp scripts/db/v004/ tests/unit/test_types.cpp
git commit -m "feat: add provider_meta field to DnsRecord and records table"
```

---

### Task 2: Cloudflare Zone ID Resolution

**Goal:** Implement zone name → Cloudflare zone ID lookup with caching.

**Files:**
- Modify: `include/providers/CloudflareProvider.hpp` (add httplib client, zone ID cache, helpers)
- Modify: `src/providers/CloudflareProvider.cpp` (implement zone ID resolution)
- Test: `tests/unit/test_cloudflare_provider.cpp` (new)

**Step 1: Write failing tests for zone ID response parsing**

Create `tests/unit/test_cloudflare_provider.cpp`:

```cpp
#include "providers/CloudflareProvider.hpp"

#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "common/Types.hpp"

using dns::common::DnsRecord;
using dns::providers::CloudflareProvider;

// --- parseZoneIdResponse tests ---

TEST(CloudflareZoneIdTest, ParsesZoneId) {
  std::string sJson = R"({
    "success": true,
    "result": [{"id": "abc123def456", "name": "example.com"}]
  })";
  auto sId = CloudflareProvider::parseZoneIdResponse(sJson, "example.com");
  EXPECT_EQ(sId, "abc123def456");
}

TEST(CloudflareZoneIdTest, ThrowsWhenZoneNotFound) {
  std::string sJson = R"({
    "success": true,
    "result": []
  })";
  EXPECT_THROW(
      CloudflareProvider::parseZoneIdResponse(sJson, "missing.com"),
      dns::common::ProviderError);
}

TEST(CloudflareZoneIdTest, ThrowsOnApiError) {
  std::string sJson = R"({
    "success": false,
    "errors": [{"code": 9103, "message": "Unknown X-Auth-Key"}]
  })";
  EXPECT_THROW(
      CloudflareProvider::parseZoneIdResponse(sJson, "example.com"),
      dns::common::ProviderError);
}
```

**Step 2: Run tests to verify they fail**

```bash
cmake --build build --parallel && build/tests/dns-tests --gtest_filter="CloudflareZoneId*"
```

Expected: FAIL — `parseZoneIdResponse` does not exist.

**Step 3: Update CloudflareProvider header**

In `include/providers/CloudflareProvider.hpp`:

```cpp
#pragma once

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>

#include "providers/IProvider.hpp"

namespace httplib {
class Client;
}

namespace dns::providers {

/// Cloudflare API v4 provider implementation.
class CloudflareProvider : public IProvider {
 public:
  CloudflareProvider(std::string sApiEndpoint, std::string sToken,
                     nlohmann::json jConfig = nlohmann::json::object());
  ~CloudflareProvider() override;

  std::string name() const override;
  common::HealthStatus testConnectivity() override;
  std::vector<common::DnsRecord> listRecords(const std::string& sZoneName) override;
  common::PushResult createRecord(const std::string& sZoneName,
                                  const common::DnsRecord& drRecord) override;
  common::PushResult updateRecord(const std::string& sZoneName,
                                  const common::DnsRecord& drRecord) override;
  bool deleteRecord(const std::string& sZoneName,
                    const std::string& sProviderRecordId) override;

  /// Parse zone ID from Cloudflare /zones?name= response.
  /// Public for unit testing.
  static std::string parseZoneIdResponse(const std::string& sJson,
                                         const std::string& sZoneName);

  /// Parse DNS records from Cloudflare /dns_records response.
  /// Public for unit testing.
  static std::vector<common::DnsRecord> parseRecordsResponse(const std::string& sJson);

 private:
  std::string _sApiEndpoint;
  std::string _sToken;
  std::string _sAccountId;
  nlohmann::json _jConfig;
  std::unique_ptr<httplib::Client> _upClient;

  /// Cached zone name → Cloudflare zone ID map.
  std::unordered_map<std::string, std::string> _mZoneIdCache;

  /// Resolve zone name to Cloudflare zone ID (cached).
  std::string resolveZoneId(const std::string& sZoneName);

  /// Build the JSON body for a create/update record request.
  static nlohmann::json buildRecordBody(const common::DnsRecord& drRecord);
};

}  // namespace dns::providers
```

**Step 4: Implement parseZoneIdResponse**

In `src/providers/CloudflareProvider.cpp`, add:

```cpp
#include "providers/CloudflareProvider.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "common/Errors.hpp"
#include "common/Logger.hpp"

namespace dns::providers {

using json = nlohmann::json;

CloudflareProvider::CloudflareProvider(std::string sApiEndpoint, std::string sToken,
                                       nlohmann::json jConfig)
    : _sApiEndpoint(std::move(sApiEndpoint)),
      _sToken(std::move(sToken)),
      _sAccountId(jConfig.value("account_id", "")),
      _jConfig(std::move(jConfig)),
      _upClient(std::make_unique<httplib::Client>(_sApiEndpoint)) {
  _upClient->set_default_headers({
      {"Authorization", "Bearer " + _sToken},
      {"Content-Type", "application/json"},
  });
  _upClient->set_connection_timeout(10);
  _upClient->set_read_timeout(30);
}

CloudflareProvider::~CloudflareProvider() = default;

std::string CloudflareProvider::name() const { return "cloudflare"; }

std::string CloudflareProvider::parseZoneIdResponse(const std::string& sJson,
                                                     const std::string& sZoneName) {
  auto jResp = json::parse(sJson);

  if (!jResp.value("success", false)) {
    std::string sError = "Cloudflare API error";
    if (jResp.contains("errors") && !jResp["errors"].empty()) {
      sError = jResp["errors"][0].value("message", sError);
    }
    throw common::ProviderError("CF_API_ERROR", sError);
  }

  auto& jResult = jResp.at("result");
  if (jResult.empty()) {
    throw common::ProviderError("CF_ZONE_NOT_FOUND",
                                "Zone '" + sZoneName + "' not found in Cloudflare account");
  }

  return jResult[0].at("id").get<std::string>();
}

std::string CloudflareProvider::resolveZoneId(const std::string& sZoneName) {
  auto it = _mZoneIdCache.find(sZoneName);
  if (it != _mZoneIdCache.end()) return it->second;

  std::string sPath = "/client/v4/zones?name=" + sZoneName + "&status=active";
  auto res = _upClient->Get(sPath);
  if (!res) {
    throw common::ProviderError("CF_UNREACHABLE",
                                "Failed to connect to Cloudflare at " + _sApiEndpoint);
  }
  if (res->status != 200) {
    throw common::ProviderError("CF_ZONE_LOOKUP_FAILED",
                                "Cloudflare returned status " + std::to_string(res->status));
  }

  auto sZoneId = parseZoneIdResponse(res->body, sZoneName);
  _mZoneIdCache[sZoneName] = sZoneId;
  return sZoneId;
}

// Remaining methods — stubs for now, implemented in Task 3 and 4
common::HealthStatus CloudflareProvider::testConnectivity() {
  throw std::runtime_error{"not implemented"};
}

std::vector<common::DnsRecord> CloudflareProvider::listRecords(
    const std::string& /*sZoneName*/) {
  throw std::runtime_error{"not implemented"};
}

common::PushResult CloudflareProvider::createRecord(const std::string& /*sZoneName*/,
                                                    const common::DnsRecord& /*drRecord*/) {
  throw std::runtime_error{"not implemented"};
}

common::PushResult CloudflareProvider::updateRecord(const std::string& /*sZoneName*/,
                                                    const common::DnsRecord& /*drRecord*/) {
  throw std::runtime_error{"not implemented"};
}

bool CloudflareProvider::deleteRecord(const std::string& /*sZoneName*/,
                                      const std::string& /*sProviderRecordId*/) {
  throw std::runtime_error{"not implemented"};
}

}  // namespace dns::providers
```

**Step 5: Run tests to verify they pass**

```bash
cmake --build build --parallel && build/tests/dns-tests --gtest_filter="CloudflareZoneId*"
```

**Step 6: Commit**

```bash
git add include/providers/CloudflareProvider.hpp src/providers/CloudflareProvider.cpp \
  tests/unit/test_cloudflare_provider.cpp
git commit -m "feat(cloudflare): implement zone ID resolution with caching"
```

---

### Task 3: Cloudflare — testConnectivity + listRecords

**Goal:** Implement connectivity check and record listing with JSON parsing.

**Files:**
- Modify: `src/providers/CloudflareProvider.cpp`
- Modify: `tests/unit/test_cloudflare_provider.cpp`

**Step 1: Write failing tests for parseRecordsResponse**

Add to `tests/unit/test_cloudflare_provider.cpp`:

```cpp
// --- parseRecordsResponse tests ---

TEST(CloudflareParseTest, EmptyRecordList) {
  std::string sJson = R"({
    "success": true,
    "result": [],
    "result_info": {"page": 1, "total_pages": 1}
  })";
  auto vRecords = CloudflareProvider::parseRecordsResponse(sJson);
  EXPECT_TRUE(vRecords.empty());
}

TEST(CloudflareParseTest, SingleARecord) {
  std::string sJson = R"({
    "success": true,
    "result": [{
      "id": "rec-uuid-1",
      "name": "www.example.com",
      "type": "A",
      "content": "192.168.1.1",
      "ttl": 300,
      "proxied": false
    }],
    "result_info": {"page": 1, "total_pages": 1}
  })";
  auto vRecords = CloudflareProvider::parseRecordsResponse(sJson);
  ASSERT_EQ(vRecords.size(), 1u);
  EXPECT_EQ(vRecords[0].sProviderRecordId, "rec-uuid-1");
  EXPECT_EQ(vRecords[0].sName, "www.example.com");
  EXPECT_EQ(vRecords[0].sType, "A");
  EXPECT_EQ(vRecords[0].uTtl, 300u);
  EXPECT_EQ(vRecords[0].sValue, "192.168.1.1");
  EXPECT_EQ(vRecords[0].iPriority, 0);
}

TEST(CloudflareParseTest, ProxiedARecord) {
  std::string sJson = R"({
    "success": true,
    "result": [{
      "id": "rec-uuid-2",
      "name": "app.example.com",
      "type": "A",
      "content": "10.0.0.1",
      "ttl": 1,
      "proxied": true
    }],
    "result_info": {"page": 1, "total_pages": 1}
  })";
  auto vRecords = CloudflareProvider::parseRecordsResponse(sJson);
  ASSERT_EQ(vRecords.size(), 1u);
  EXPECT_EQ(vRecords[0].uTtl, 1u);  // Cloudflare uses TTL=1 for proxied (auto)
  EXPECT_TRUE(vRecords[0].jProviderMeta.value("proxied", false));
}

TEST(CloudflareParseTest, MxRecordWithPriority) {
  std::string sJson = R"({
    "success": true,
    "result": [{
      "id": "rec-uuid-3",
      "name": "example.com",
      "type": "MX",
      "content": "mail.example.com",
      "ttl": 3600,
      "priority": 10,
      "proxied": false
    }],
    "result_info": {"page": 1, "total_pages": 1}
  })";
  auto vRecords = CloudflareProvider::parseRecordsResponse(sJson);
  ASSERT_EQ(vRecords.size(), 1u);
  EXPECT_EQ(vRecords[0].sType, "MX");
  EXPECT_EQ(vRecords[0].iPriority, 10);
  EXPECT_EQ(vRecords[0].sValue, "mail.example.com");
}

TEST(CloudflareParseTest, MultipleRecords) {
  std::string sJson = R"({
    "success": true,
    "result": [
      {"id": "r1", "name": "example.com", "type": "A", "content": "1.1.1.1", "ttl": 300, "proxied": false},
      {"id": "r2", "name": "example.com", "type": "AAAA", "content": "::1", "ttl": 300, "proxied": false},
      {"id": "r3", "name": "www.example.com", "type": "CNAME", "content": "example.com", "ttl": 300, "proxied": true}
    ],
    "result_info": {"page": 1, "total_pages": 1}
  })";
  auto vRecords = CloudflareProvider::parseRecordsResponse(sJson);
  ASSERT_EQ(vRecords.size(), 3u);
  EXPECT_EQ(vRecords[2].sType, "CNAME");
  EXPECT_TRUE(vRecords[2].jProviderMeta.value("proxied", false));
}

TEST(CloudflareParseTest, TxtRecord) {
  std::string sJson = R"({
    "success": true,
    "result": [{
      "id": "rec-txt-1",
      "name": "example.com",
      "type": "TXT",
      "content": "v=spf1 include:_spf.google.com ~all",
      "ttl": 3600,
      "proxied": false
    }],
    "result_info": {"page": 1, "total_pages": 1}
  })";
  auto vRecords = CloudflareProvider::parseRecordsResponse(sJson);
  ASSERT_EQ(vRecords.size(), 1u);
  EXPECT_EQ(vRecords[0].sType, "TXT");
  EXPECT_EQ(vRecords[0].sValue, "v=spf1 include:_spf.google.com ~all");
}
```

**Step 2: Run tests to verify they fail**

```bash
cmake --build build --parallel && build/tests/dns-tests --gtest_filter="CloudflareParse*"
```

**Step 3: Implement parseRecordsResponse and testConnectivity**

In `src/providers/CloudflareProvider.cpp`:

```cpp
std::vector<common::DnsRecord> CloudflareProvider::parseRecordsResponse(
    const std::string& sJson) {
  std::vector<common::DnsRecord> vRecords;
  auto jResp = json::parse(sJson);

  if (!jResp.value("success", false)) {
    std::string sError = "Cloudflare API error";
    if (jResp.contains("errors") && !jResp["errors"].empty()) {
      sError = jResp["errors"][0].value("message", sError);
    }
    throw common::ProviderError("CF_API_ERROR", sError);
  }

  for (const auto& jRec : jResp.at("result")) {
    common::DnsRecord dr;
    dr.sProviderRecordId = jRec.at("id").get<std::string>();
    dr.sName = jRec.at("name").get<std::string>();
    dr.sType = jRec.at("type").get<std::string>();
    dr.uTtl = jRec.at("ttl").get<uint32_t>();
    dr.sValue = jRec.at("content").get<std::string>();
    dr.iPriority = jRec.value("priority", 0);

    // Capture provider-specific metadata
    bool bProxied = jRec.value("proxied", false);
    dr.jProviderMeta = {{"proxied", bProxied}};

    vRecords.push_back(std::move(dr));
  }

  return vRecords;
}

common::HealthStatus CloudflareProvider::testConnectivity() {
  auto spLog = common::Logger::get();
  try {
    auto res = _upClient->Get("/client/v4/user/tokens/verify");
    if (!res) {
      spLog->warn("Cloudflare {}: connection failed", _sApiEndpoint);
      return common::HealthStatus::Unreachable;
    }
    if (res->status == 200) {
      auto jResp = json::parse(res->body);
      if (jResp.value("success", false)) {
        return common::HealthStatus::Ok;
      }
    }
    spLog->warn("Cloudflare {}: unexpected status {}", _sApiEndpoint, res->status);
    return common::HealthStatus::Degraded;
  } catch (const std::exception& ex) {
    spLog->error("Cloudflare {}: connectivity test failed: {}", _sApiEndpoint, ex.what());
    return common::HealthStatus::Unreachable;
  }
}
```

**Step 4: Implement listRecords with pagination**

```cpp
std::vector<common::DnsRecord> CloudflareProvider::listRecords(
    const std::string& sZoneName) {
  auto spLog = common::Logger::get();
  auto sZoneId = resolveZoneId(sZoneName);

  std::vector<common::DnsRecord> vAll;
  int iPage = 1;
  int iTotalPages = 1;

  while (iPage <= iTotalPages) {
    std::string sPath = "/client/v4/zones/" + sZoneId +
                        "/dns_records?per_page=100&page=" + std::to_string(iPage);
    auto res = _upClient->Get(sPath);
    if (!res) {
      throw common::ProviderError("CF_UNREACHABLE",
                                  "Failed to connect to Cloudflare at " + _sApiEndpoint);
    }
    if (res->status != 200) {
      throw common::ProviderError("CF_LIST_FAILED",
                                  "Cloudflare returned status " + std::to_string(res->status));
    }

    auto jResp = json::parse(res->body);
    auto vPage = parseRecordsResponse(res->body);
    vAll.insert(vAll.end(), vPage.begin(), vPage.end());

    if (jResp.contains("result_info")) {
      iTotalPages = jResp["result_info"].value("total_pages", 1);
    }
    ++iPage;
  }

  spLog->debug("Cloudflare: listed {} records for zone {} ({})", vAll.size(), sZoneName,
               sZoneId);
  return vAll;
}
```

**Step 5: Run tests**

```bash
cmake --build build --parallel && build/tests/dns-tests --gtest_filter="Cloudflare*"
```

**Step 6: Commit**

```bash
git add src/providers/CloudflareProvider.cpp tests/unit/test_cloudflare_provider.cpp
git commit -m "feat(cloudflare): implement testConnectivity, listRecords, and response parsing"
```

---

### Task 4: Cloudflare — CRUD Operations

**Goal:** Implement createRecord, updateRecord, deleteRecord for Cloudflare API v4.

**Files:**
- Modify: `src/providers/CloudflareProvider.cpp`
- Modify: `tests/unit/test_cloudflare_provider.cpp`

**Step 1: Write tests for buildRecordBody**

Add to `tests/unit/test_cloudflare_provider.cpp`:

```cpp
TEST(CloudflareBuildBodyTest, SimpleARecord) {
  dns::common::DnsRecord dr;
  dr.sName = "www.example.com";
  dr.sType = "A";
  dr.uTtl = 300;
  dr.sValue = "192.168.1.1";

  auto jBody = CloudflareProvider::buildRecordBody(dr);
  EXPECT_EQ(jBody["name"], "www.example.com");
  EXPECT_EQ(jBody["type"], "A");
  EXPECT_EQ(jBody["content"], "192.168.1.1");
  EXPECT_EQ(jBody["ttl"], 300);
  EXPECT_FALSE(jBody.value("proxied", true));
}

TEST(CloudflareBuildBodyTest, ProxiedRecord) {
  dns::common::DnsRecord dr;
  dr.sName = "app.example.com";
  dr.sType = "A";
  dr.uTtl = 1;
  dr.sValue = "10.0.0.1";
  dr.jProviderMeta = {{"proxied", true}};

  auto jBody = CloudflareProvider::buildRecordBody(dr);
  EXPECT_TRUE(jBody["proxied"].get<bool>());
  EXPECT_EQ(jBody["ttl"], 1);
}

TEST(CloudflareBuildBodyTest, MxRecordWithPriority) {
  dns::common::DnsRecord dr;
  dr.sName = "example.com";
  dr.sType = "MX";
  dr.uTtl = 3600;
  dr.sValue = "mail.example.com";
  dr.iPriority = 10;

  auto jBody = CloudflareProvider::buildRecordBody(dr);
  EXPECT_EQ(jBody["priority"], 10);
  EXPECT_EQ(jBody["content"], "mail.example.com");
}
```

**Step 2: Run tests to verify they fail**

```bash
cmake --build build --parallel && build/tests/dns-tests --gtest_filter="CloudflareBuildBody*"
```

**Step 3: Implement buildRecordBody and CRUD**

Add to `src/providers/CloudflareProvider.cpp`:

```cpp
nlohmann::json CloudflareProvider::buildRecordBody(const common::DnsRecord& drRecord) {
  json jBody = {
      {"type", drRecord.sType},
      {"name", drRecord.sName},
      {"content", drRecord.sValue},
      {"ttl", drRecord.uTtl},
  };

  // MX/SRV have priority as a separate field in Cloudflare API
  if ((drRecord.sType == "MX" || drRecord.sType == "SRV") && drRecord.iPriority > 0) {
    jBody["priority"] = drRecord.iPriority;
  }

  // Proxy support — only for A/AAAA/CNAME
  bool bProxied = false;
  if (!drRecord.jProviderMeta.is_null()) {
    bProxied = drRecord.jProviderMeta.value("proxied", false);
  }
  if (drRecord.sType == "A" || drRecord.sType == "AAAA" || drRecord.sType == "CNAME") {
    jBody["proxied"] = bProxied;
  }

  return jBody;
}

common::PushResult CloudflareProvider::createRecord(const std::string& sZoneName,
                                                    const common::DnsRecord& drRecord) {
  auto spLog = common::Logger::get();
  auto sZoneId = resolveZoneId(sZoneName);
  std::string sPath = "/client/v4/zones/" + sZoneId + "/dns_records";

  auto jBody = buildRecordBody(drRecord);
  auto res = _upClient->Post(sPath, jBody.dump(), "application/json");
  if (!res) {
    return {false, "", "Failed to connect to Cloudflare"};
  }

  auto jResp = json::parse(res->body);
  if (res->status != 200 || !jResp.value("success", false)) {
    std::string sError = "Cloudflare create failed";
    if (jResp.contains("errors") && !jResp["errors"].empty()) {
      sError = jResp["errors"][0].value("message", sError);
    }
    return {false, "", sError};
  }

  std::string sNewId = jResp["result"].at("id").get<std::string>();
  spLog->info("Cloudflare: created record {} in zone {}", sNewId, sZoneName);
  return {true, sNewId, ""};
}

common::PushResult CloudflareProvider::updateRecord(const std::string& sZoneName,
                                                    const common::DnsRecord& drRecord) {
  auto spLog = common::Logger::get();
  auto sZoneId = resolveZoneId(sZoneName);
  std::string sPath = "/client/v4/zones/" + sZoneId + "/dns_records/" +
                      drRecord.sProviderRecordId;

  auto jBody = buildRecordBody(drRecord);
  auto res = _upClient->Patch(sPath, jBody.dump(), "application/json");
  if (!res) {
    return {false, "", "Failed to connect to Cloudflare"};
  }

  auto jResp = json::parse(res->body);
  if (res->status != 200 || !jResp.value("success", false)) {
    std::string sError = "Cloudflare update failed";
    if (jResp.contains("errors") && !jResp["errors"].empty()) {
      sError = jResp["errors"][0].value("message", sError);
    }
    return {false, "", sError};
  }

  std::string sNewId = jResp["result"].at("id").get<std::string>();
  spLog->info("Cloudflare: updated record {} in zone {}", sNewId, sZoneName);
  return {true, sNewId, ""};
}

bool CloudflareProvider::deleteRecord(const std::string& sZoneName,
                                      const std::string& sProviderRecordId) {
  auto spLog = common::Logger::get();
  auto sZoneId = resolveZoneId(sZoneName);
  std::string sPath = "/client/v4/zones/" + sZoneId + "/dns_records/" + sProviderRecordId;

  auto res = _upClient->Delete(sPath);
  if (!res) return false;

  if (res->status != 200) return false;

  auto jResp = json::parse(res->body);
  if (!jResp.value("success", false)) return false;

  spLog->info("Cloudflare: deleted record {} from zone {}", sProviderRecordId, sZoneName);
  return true;
}
```

**Step 4: Run all Cloudflare tests**

```bash
cmake --build build --parallel && build/tests/dns-tests --gtest_filter="Cloudflare*"
```

**Step 5: Commit**

```bash
git add src/providers/CloudflareProvider.cpp tests/unit/test_cloudflare_provider.cpp
git commit -m "feat(cloudflare): implement createRecord, updateRecord, deleteRecord"
```

---

### Task 5: Cloudflare Proxy Support — IProvider + DiffEngine

**Goal:** Ensure the proxy metadata flows correctly through the diff/deployment pipeline.
DiffEngine must ignore `jProviderMeta` when comparing records (only name/type/value/ttl
matter for equality). Provider-specific metadata is preserved and passed through to providers.

**Files:**
- Modify: `src/core/DiffEngine.cpp` (no changes needed if diff already ignores extra fields)
- Modify: `src/core/DeploymentEngine.cpp` (pass `jProviderMeta` through to provider on create)
- Test: `tests/unit/test_diff_engine.cpp` (add test confirming proxy metadata is ignored in diff)

**Step 1: Write test confirming DiffEngine ignores provider metadata**

Add to `tests/unit/test_diff_engine.cpp`:

```cpp
TEST(DiffEngineComputeTest, IgnoresProviderMetaInComparison) {
  // Same record with different provider metadata → no diff
  std::vector<dns::common::DnsRecord> vDesired = {{
      .sProviderRecordId = "",
      .sName = "www.example.com",
      .sType = "A",
      .uTtl = 300,
      .sValue = "1.2.3.4",
      .iPriority = 0,
      .jProviderMeta = {{"proxied", true}},
  }};

  std::vector<dns::common::DnsRecord> vLive = {{
      .sProviderRecordId = "rec-1",
      .sName = "www.example.com",
      .sType = "A",
      .uTtl = 300,
      .sValue = "1.2.3.4",
      .iPriority = 0,
      .jProviderMeta = {{"proxied", false}},
  }};

  auto vDiffs = dns::core::DiffEngine::computeDiff(vDesired, vLive);
  EXPECT_TRUE(vDiffs.empty());  // metadata difference should not cause a diff
}
```

**Step 2: Verify this test passes** (DiffEngine already compares only name/type/value)

```bash
cmake --build build --parallel && build/tests/dns-tests --gtest_filter="DiffEngineComputeTest.IgnoresProviderMeta*"
```

If it passes, `computeDiff` already ignores metadata correctly. If it fails, the diff
logic needs adjustment (unlikely based on current key construction).

**Step 3: Update DeploymentEngine to pass provider metadata**

In `src/core/DeploymentEngine.cpp`, in the push method where records are created,
ensure the `DnsRecord` passed to `createRecord()` includes `jProviderMeta` from the
source record. This requires looking up the source record's `provider_meta` from the
database.

In the `Add` case (around line 175), after building `dr`:

```cpp
case common::DiffAction::Add: {
  common::DnsRecord dr;
  dr.sName = diff.sName;
  dr.sType = diff.sType;
  dr.sValue = diff.sSourceValue;
  dr.uTtl = diff.uTtl;
  dr.iPriority = diff.iPriority;
  // Look up provider_meta from source record if available
  auto vRecords = _rrRepo.listByZoneId(iZoneId);
  for (const auto& rec : vRecords) {
    if (rec.sName == diff.sName && rec.sType == diff.sType) {
      dr.jProviderMeta = rec.jProviderMeta;
      break;
    }
  }
  auto pushResult = upProvider->createRecord(oZone->sName, dr);
  // ... existing error handling
}
```

> **Note:** This is a naive lookup. For efficiency, build a lookup map of source records
> once before the provider loop, keyed by name+type. This avoids repeated DB queries.

**Better approach — cache records before provider loop:**

Before line 162 (the provider loop), add:

```cpp
// Build lookup map of source records for provider metadata
auto vSourceRecords = _rrRepo.listByZoneId(iZoneId);
std::map<std::string, nlohmann::json> mProviderMeta;
for (const auto& rec : vSourceRecords) {
  mProviderMeta[rec.sName + "\t" + rec.sType] = rec.jProviderMeta;
}
```

Then in the Add/Update cases, look up metadata:

```cpp
auto itMeta = mProviderMeta.find(diff.sName + "\t" + diff.sType);
if (itMeta != mProviderMeta.end()) {
  dr.jProviderMeta = itMeta->second;
}
```

**Step 4: Add RecordDiff.jProviderMeta field**

To properly carry metadata through the diff pipeline, extend `RecordDiff` in
`include/common/Types.hpp`:

```cpp
struct RecordDiff {
  DiffAction action;
  std::string sName;
  std::string sType;
  std::string sProviderValue;
  std::string sSourceValue;
  uint32_t uTtl = 300;
  int iPriority = 0;
  nlohmann::json jProviderMeta;  // Provider metadata from source record
};
```

Update `DiffEngine::computeDiff()` to copy `jProviderMeta` from the desired record into
the diff entry (for Add/Update actions), and from the live record (for Drift actions).

**Step 5: Run all tests**

```bash
cmake --build build --parallel && build/tests/dns-tests
```

**Step 6: Commit**

```bash
git add include/common/Types.hpp src/core/DiffEngine.cpp src/core/DeploymentEngine.cpp \
  tests/unit/test_diff_engine.cpp
git commit -m "feat: flow provider metadata through diff and deployment pipeline"
```

---

### Task 6: Cloudflare Proxy Support — UI

**Goal:** Add proxy toggle to the record form when the zone's view contains a Cloudflare
provider. Show proxy status in the records table.

**Files:**
- Modify: `ui/src/types/index.ts` (add `provider_meta` to `DnsRecord` and `RecordCreate`)
- Modify: `ui/src/views/ZoneDetailView.vue` (add proxy toggle, show proxy badge)

**Step 1: Extend TypeScript types**

In `ui/src/types/index.ts`, modify:

```typescript
export interface DnsRecord {
  id: number
  zone_id: number
  name: string
  type: string
  ttl: number
  value_template: string
  priority: number
  provider_meta: Record<string, unknown> | null
  last_audit_id: number | null
  created_at: number
  updated_at: number
}

export interface RecordCreate {
  name: string
  type: string
  ttl?: number
  value_template: string
  priority?: number
  provider_meta?: Record<string, unknown>
}
```

**Step 2: Detect Cloudflare provider in zone's view**

In `ZoneDetailView.vue`, add a computed that checks if the zone's view has a Cloudflare
provider:

```typescript
const hasCloudflareProvider = computed(() => {
  // Check if any provider in the zone's view is of type 'cloudflare'
  // This requires fetching the view's providers
  return viewProviders.value.some(p => p.type === 'cloudflare')
})
```

This requires fetching the zone's view and its attached providers when the zone detail
loads.

**Step 3: Add proxy toggle to record form**

When `hasCloudflareProvider` is true and the record type is A, AAAA, or CNAME, show a
toggle switch:

```vue
<div v-if="hasCloudflareProvider && ['A', 'AAAA', 'CNAME'].includes(form.type)" class="field">
  <label>Cloudflare Proxy</label>
  <ToggleSwitch v-model="form.proxied" />
  <small>Route traffic through Cloudflare's CDN/WAF</small>
</div>
```

Map `form.proxied` to/from `provider_meta.proxied` when saving/loading records.

**Step 4: Show proxy badge in records table**

Add a template column or badge that shows a shield icon when a record is proxied:

```vue
<Column header="Proxy" v-if="hasCloudflareProvider">
  <template #body="{ data }">
    <Tag v-if="data.provider_meta?.proxied" value="Proxied" severity="info" />
  </template>
</Column>
```

**Step 5: Test manually in dev server**

```bash
cd ui && npm run dev
```

Navigate to a zone with a Cloudflare provider and verify:
- Proxy toggle appears for A/AAAA/CNAME records
- Proxy badge shows in records table
- Toggle doesn't appear for MX/TXT/etc.

**Step 6: Commit**

```bash
git add ui/src/types/index.ts ui/src/views/ZoneDetailView.vue
git commit -m "feat(ui): add Cloudflare proxy toggle and badge to zone records"
```

---

### Task 7: DigitalOcean — testConnectivity + listRecords

**Goal:** Implement DigitalOcean API v2 connectivity check and record listing.

**Files:**
- Modify: `include/providers/DigitalOceanProvider.hpp` (add httplib client, helpers)
- Modify: `src/providers/DigitalOceanProvider.cpp`
- Create: `tests/unit/test_digitalocean_provider.cpp`

**Step 1: Write failing tests**

Create `tests/unit/test_digitalocean_provider.cpp`:

```cpp
#include "providers/DigitalOceanProvider.hpp"

#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "common/Types.hpp"

using dns::common::DnsRecord;
using dns::providers::DigitalOceanProvider;

TEST(DoParseTest, EmptyRecordList) {
  std::string sJson = R"({
    "domain_records": [],
    "links": {},
    "meta": {"total": 0}
  })";
  auto vRecords = DigitalOceanProvider::parseRecordsResponse(sJson, "example.com");
  EXPECT_TRUE(vRecords.empty());
}

TEST(DoParseTest, SingleARecord) {
  std::string sJson = R"({
    "domain_records": [{
      "id": 12345,
      "type": "A",
      "name": "www",
      "data": "192.168.1.1",
      "ttl": 300,
      "priority": null
    }],
    "links": {},
    "meta": {"total": 1}
  })";
  auto vRecords = DigitalOceanProvider::parseRecordsResponse(sJson, "example.com");
  ASSERT_EQ(vRecords.size(), 1u);
  EXPECT_EQ(vRecords[0].sProviderRecordId, "12345");
  EXPECT_EQ(vRecords[0].sName, "www.example.com");  // Converted to FQDN
  EXPECT_EQ(vRecords[0].sType, "A");
  EXPECT_EQ(vRecords[0].uTtl, 300u);
  EXPECT_EQ(vRecords[0].sValue, "192.168.1.1");
}

TEST(DoParseTest, ApexRecord) {
  std::string sJson = R"({
    "domain_records": [{
      "id": 12346,
      "type": "A",
      "name": "@",
      "data": "10.0.0.1",
      "ttl": 1800,
      "priority": null
    }],
    "links": {},
    "meta": {"total": 1}
  })";
  auto vRecords = DigitalOceanProvider::parseRecordsResponse(sJson, "example.com");
  ASSERT_EQ(vRecords.size(), 1u);
  EXPECT_EQ(vRecords[0].sName, "example.com");  // @ converted to zone apex
}

TEST(DoParseTest, MxRecordWithPriority) {
  std::string sJson = R"({
    "domain_records": [{
      "id": 12347,
      "type": "MX",
      "name": "@",
      "data": "mail.example.com.",
      "ttl": 3600,
      "priority": 10
    }],
    "links": {},
    "meta": {"total": 1}
  })";
  auto vRecords = DigitalOceanProvider::parseRecordsResponse(sJson, "example.com");
  ASSERT_EQ(vRecords.size(), 1u);
  EXPECT_EQ(vRecords[0].sType, "MX");
  EXPECT_EQ(vRecords[0].iPriority, 10);
  EXPECT_EQ(vRecords[0].sValue, "mail.example.com.");
}

TEST(DoParseTest, CnameRecord) {
  std::string sJson = R"({
    "domain_records": [{
      "id": 12348,
      "type": "CNAME",
      "name": "blog",
      "data": "example.com.",
      "ttl": 300,
      "priority": null
    }],
    "links": {},
    "meta": {"total": 1}
  })";
  auto vRecords = DigitalOceanProvider::parseRecordsResponse(sJson, "example.com");
  ASSERT_EQ(vRecords.size(), 1u);
  EXPECT_EQ(vRecords[0].sName, "blog.example.com");
  EXPECT_EQ(vRecords[0].sType, "CNAME");
}

TEST(DoParseTest, MultipleRecords) {
  std::string sJson = R"({
    "domain_records": [
      {"id": 1, "type": "A", "name": "@", "data": "1.1.1.1", "ttl": 300, "priority": null},
      {"id": 2, "type": "A", "name": "www", "data": "1.1.1.1", "ttl": 300, "priority": null},
      {"id": 3, "type": "MX", "name": "@", "data": "mx.example.com.", "ttl": 3600, "priority": 10}
    ],
    "links": {},
    "meta": {"total": 3}
  })";
  auto vRecords = DigitalOceanProvider::parseRecordsResponse(sJson, "example.com");
  ASSERT_EQ(vRecords.size(), 3u);
}
```

**Step 2: Run tests to verify they fail**

```bash
cmake --build build --parallel && build/tests/dns-tests --gtest_filter="DoParse*"
```

**Step 3: Update DigitalOceanProvider header**

```cpp
#pragma once

#include <memory>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "providers/IProvider.hpp"

namespace httplib {
class Client;
}

namespace dns::providers {

/// DigitalOcean API v2 /domains provider implementation.
class DigitalOceanProvider : public IProvider {
 public:
  DigitalOceanProvider(std::string sApiEndpoint, std::string sToken,
                       nlohmann::json jConfig = nlohmann::json::object());
  ~DigitalOceanProvider() override;

  std::string name() const override;
  common::HealthStatus testConnectivity() override;
  std::vector<common::DnsRecord> listRecords(const std::string& sZoneName) override;
  common::PushResult createRecord(const std::string& sZoneName,
                                  const common::DnsRecord& drRecord) override;
  common::PushResult updateRecord(const std::string& sZoneName,
                                  const common::DnsRecord& drRecord) override;
  bool deleteRecord(const std::string& sZoneName,
                    const std::string& sProviderRecordId) override;

  /// Parse DNS records from DigitalOcean /domains/{domain}/records response.
  /// Converts relative names to FQDNs using the zone name.
  /// Public for unit testing.
  static std::vector<common::DnsRecord> parseRecordsResponse(const std::string& sJson,
                                                              const std::string& sZoneName);

  /// Convert DigitalOcean relative record name to FQDN.
  /// "@" → zoneName, "www" → "www.zoneName"
  static std::string toFqdn(const std::string& sName, const std::string& sZoneName);

  /// Convert FQDN to DigitalOcean relative record name.
  /// "example.com" → "@", "www.example.com" → "www"
  static std::string toRelative(const std::string& sFqdn, const std::string& sZoneName);

 private:
  std::string _sApiEndpoint;
  std::string _sToken;
  nlohmann::json _jConfig;
  std::unique_ptr<httplib::Client> _upClient;
};

}  // namespace dns::providers
```

**Step 4: Implement**

```cpp
#include "providers/DigitalOceanProvider.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "common/Errors.hpp"
#include "common/Logger.hpp"

namespace dns::providers {

using json = nlohmann::json;

DigitalOceanProvider::DigitalOceanProvider(std::string sApiEndpoint, std::string sToken,
                                             nlohmann::json jConfig)
    : _sApiEndpoint(std::move(sApiEndpoint)),
      _sToken(std::move(sToken)),
      _jConfig(std::move(jConfig)),
      _upClient(std::make_unique<httplib::Client>(_sApiEndpoint)) {
  _upClient->set_default_headers({
      {"Authorization", "Bearer " + _sToken},
      {"Content-Type", "application/json"},
  });
  _upClient->set_connection_timeout(10);
  _upClient->set_read_timeout(30);
}

DigitalOceanProvider::~DigitalOceanProvider() = default;

std::string DigitalOceanProvider::name() const { return "digitalocean"; }

std::string DigitalOceanProvider::toFqdn(const std::string& sName,
                                          const std::string& sZoneName) {
  if (sName == "@" || sName.empty()) return sZoneName;
  return sName + "." + sZoneName;
}

std::string DigitalOceanProvider::toRelative(const std::string& sFqdn,
                                              const std::string& sZoneName) {
  if (sFqdn == sZoneName) return "@";
  std::string sSuffix = "." + sZoneName;
  if (sFqdn.size() > sSuffix.size() &&
      sFqdn.compare(sFqdn.size() - sSuffix.size(), sSuffix.size(), sSuffix) == 0) {
    return sFqdn.substr(0, sFqdn.size() - sSuffix.size());
  }
  return sFqdn;  // Fallback — return as-is
}

std::vector<common::DnsRecord> DigitalOceanProvider::parseRecordsResponse(
    const std::string& sJson, const std::string& sZoneName) {
  std::vector<common::DnsRecord> vRecords;
  auto jResp = json::parse(sJson);

  for (const auto& jRec : jResp.at("domain_records")) {
    common::DnsRecord dr;
    dr.sProviderRecordId = std::to_string(jRec.at("id").get<int64_t>());
    dr.sName = toFqdn(jRec.at("name").get<std::string>(), sZoneName);
    dr.sType = jRec.at("type").get<std::string>();
    dr.uTtl = jRec.at("ttl").get<uint32_t>();
    dr.sValue = jRec.at("data").get<std::string>();
    dr.iPriority = jRec.value("priority", 0);
    // DigitalOcean returns null for priority on non-MX/SRV records
    if (jRec["priority"].is_null()) {
      dr.iPriority = 0;
    }

    vRecords.push_back(std::move(dr));
  }

  return vRecords;
}

common::HealthStatus DigitalOceanProvider::testConnectivity() {
  auto spLog = common::Logger::get();
  try {
    auto res = _upClient->Get("/v2/account");
    if (!res) {
      spLog->warn("DigitalOcean {}: connection failed", _sApiEndpoint);
      return common::HealthStatus::Unreachable;
    }
    if (res->status == 200) {
      return common::HealthStatus::Ok;
    }
    spLog->warn("DigitalOcean {}: unexpected status {}", _sApiEndpoint, res->status);
    return common::HealthStatus::Degraded;
  } catch (const std::exception& ex) {
    spLog->error("DigitalOcean {}: connectivity test failed: {}", _sApiEndpoint, ex.what());
    return common::HealthStatus::Unreachable;
  }
}

std::vector<common::DnsRecord> DigitalOceanProvider::listRecords(
    const std::string& sZoneName) {
  auto spLog = common::Logger::get();

  std::vector<common::DnsRecord> vAll;
  int iPage = 1;
  bool bHasMore = true;

  while (bHasMore) {
    std::string sPath = "/v2/domains/" + sZoneName +
                        "/records?per_page=200&page=" + std::to_string(iPage);
    auto res = _upClient->Get(sPath);
    if (!res) {
      throw common::ProviderError("DO_UNREACHABLE",
                                  "Failed to connect to DigitalOcean at " + _sApiEndpoint);
    }
    if (res->status != 200) {
      throw common::ProviderError("DO_LIST_FAILED",
                                  "DigitalOcean returned status " + std::to_string(res->status));
    }

    auto jResp = json::parse(res->body);
    auto vPage = parseRecordsResponse(res->body, sZoneName);
    vAll.insert(vAll.end(), vPage.begin(), vPage.end());

    // Check pagination — DigitalOcean uses links.pages.next
    bHasMore = jResp.contains("links") && jResp["links"].contains("pages") &&
               jResp["links"]["pages"].contains("next");
    ++iPage;
  }

  spLog->debug("DigitalOcean: listed {} records for zone {}", vAll.size(), sZoneName);
  return vAll;
}

// CRUD stubs — implemented in Task 8
common::PushResult DigitalOceanProvider::createRecord(const std::string& /*sZoneName*/,
                                                      const common::DnsRecord& /*drRecord*/) {
  throw std::runtime_error{"not implemented"};
}

common::PushResult DigitalOceanProvider::updateRecord(const std::string& /*sZoneName*/,
                                                      const common::DnsRecord& /*drRecord*/) {
  throw std::runtime_error{"not implemented"};
}

bool DigitalOceanProvider::deleteRecord(const std::string& /*sZoneName*/,
                                        const std::string& /*sProviderRecordId*/) {
  throw std::runtime_error{"not implemented"};
}

}  // namespace dns::providers
```

**Step 5: Run tests**

```bash
cmake --build build --parallel && build/tests/dns-tests --gtest_filter="DoParse*"
```

**Step 6: Commit**

```bash
git add include/providers/DigitalOceanProvider.hpp src/providers/DigitalOceanProvider.cpp \
  tests/unit/test_digitalocean_provider.cpp
git commit -m "feat(digitalocean): implement testConnectivity, listRecords, and response parsing"
```

---

### Task 8: DigitalOcean — CRUD Operations

**Goal:** Implement createRecord, updateRecord, deleteRecord for DigitalOcean API v2.

**Files:**
- Modify: `src/providers/DigitalOceanProvider.cpp`
- Modify: `tests/unit/test_digitalocean_provider.cpp`

**Step 1: Write tests for name conversion helpers**

Add to `tests/unit/test_digitalocean_provider.cpp`:

```cpp
TEST(DoNameConversionTest, ToFqdnApex) {
  EXPECT_EQ(DigitalOceanProvider::toFqdn("@", "example.com"), "example.com");
}

TEST(DoNameConversionTest, ToFqdnSubdomain) {
  EXPECT_EQ(DigitalOceanProvider::toFqdn("www", "example.com"), "www.example.com");
}

TEST(DoNameConversionTest, ToFqdnEmpty) {
  EXPECT_EQ(DigitalOceanProvider::toFqdn("", "example.com"), "example.com");
}

TEST(DoNameConversionTest, ToRelativeApex) {
  EXPECT_EQ(DigitalOceanProvider::toRelative("example.com", "example.com"), "@");
}

TEST(DoNameConversionTest, ToRelativeSubdomain) {
  EXPECT_EQ(DigitalOceanProvider::toRelative("www.example.com", "example.com"), "www");
}

TEST(DoNameConversionTest, ToRelativeDeep) {
  EXPECT_EQ(DigitalOceanProvider::toRelative("a.b.example.com", "example.com"), "a.b");
}
```

**Step 2: Run tests**

```bash
cmake --build build --parallel && build/tests/dns-tests --gtest_filter="DoNameConversion*"
```

**Step 3: Implement CRUD**

Replace the stubs in `src/providers/DigitalOceanProvider.cpp`:

```cpp
common::PushResult DigitalOceanProvider::createRecord(const std::string& sZoneName,
                                                      const common::DnsRecord& drRecord) {
  auto spLog = common::Logger::get();
  std::string sPath = "/v2/domains/" + sZoneName + "/records";

  json jBody = {
      {"type", drRecord.sType},
      {"name", toRelative(drRecord.sName, sZoneName)},
      {"data", drRecord.sValue},
      {"ttl", drRecord.uTtl},
  };
  if ((drRecord.sType == "MX" || drRecord.sType == "SRV") && drRecord.iPriority > 0) {
    jBody["priority"] = drRecord.iPriority;
  }

  auto res = _upClient->Post(sPath, jBody.dump(), "application/json");
  if (!res) {
    return {false, "", "Failed to connect to DigitalOcean"};
  }
  if (res->status != 201) {
    std::string sError = "DigitalOcean create failed (status " +
                         std::to_string(res->status) + ")";
    try {
      auto jResp = json::parse(res->body);
      sError = jResp.value("message", sError);
    } catch (...) {}
    return {false, "", sError};
  }

  auto jResp = json::parse(res->body);
  std::string sNewId = std::to_string(
      jResp["domain_record"].at("id").get<int64_t>());
  spLog->info("DigitalOcean: created record {} in zone {}", sNewId, sZoneName);
  return {true, sNewId, ""};
}

common::PushResult DigitalOceanProvider::updateRecord(const std::string& sZoneName,
                                                      const common::DnsRecord& drRecord) {
  auto spLog = common::Logger::get();
  std::string sPath = "/v2/domains/" + sZoneName + "/records/" +
                      drRecord.sProviderRecordId;

  json jBody = {
      {"type", drRecord.sType},
      {"name", toRelative(drRecord.sName, sZoneName)},
      {"data", drRecord.sValue},
      {"ttl", drRecord.uTtl},
  };
  if ((drRecord.sType == "MX" || drRecord.sType == "SRV") && drRecord.iPriority > 0) {
    jBody["priority"] = drRecord.iPriority;
  }

  auto res = _upClient->Put(sPath, jBody.dump(), "application/json");
  if (!res) {
    return {false, "", "Failed to connect to DigitalOcean"};
  }
  if (res->status != 200) {
    std::string sError = "DigitalOcean update failed (status " +
                         std::to_string(res->status) + ")";
    try {
      auto jResp = json::parse(res->body);
      sError = jResp.value("message", sError);
    } catch (...) {}
    return {false, "", sError};
  }

  auto jResp = json::parse(res->body);
  std::string sNewId = std::to_string(
      jResp["domain_record"].at("id").get<int64_t>());
  spLog->info("DigitalOcean: updated record {} in zone {}", sNewId, sZoneName);
  return {true, sNewId, ""};
}

bool DigitalOceanProvider::deleteRecord(const std::string& sZoneName,
                                        const std::string& sProviderRecordId) {
  auto spLog = common::Logger::get();
  std::string sPath = "/v2/domains/" + sZoneName + "/records/" + sProviderRecordId;

  auto res = _upClient->Delete(sPath);
  if (!res) return false;
  if (res->status != 204) return false;

  spLog->info("DigitalOcean: deleted record {} from zone {}", sProviderRecordId, sZoneName);
  return true;
}
```

**Step 4: Run all DigitalOcean tests**

```bash
cmake --build build --parallel && build/tests/dns-tests --gtest_filter="Do*"
```

**Step 5: Commit**

```bash
git add src/providers/DigitalOceanProvider.cpp tests/unit/test_digitalocean_provider.cpp
git commit -m "feat(digitalocean): implement createRecord, updateRecord, deleteRecord"
```

---

### Task 9: Provider Conformance Test Suite

**Goal:** Create a test suite that validates all providers implement the `IProvider` interface
consistently. Tests use mock HTTP responses to verify JSON parsing, record ID handling, error
mapping, and pagination.

**Files:**
- Create: `tests/unit/test_provider_conformance.cpp`

**Step 1: Write the conformance test**

This test validates the public static parsing methods of each provider:

```cpp
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "common/Types.hpp"
#include "providers/CloudflareProvider.hpp"
#include "providers/DigitalOceanProvider.hpp"
#include "providers/PowerDnsProvider.hpp"

using dns::common::DnsRecord;

// --- Conformance: All providers return consistent DnsRecord structures ---

class ProviderConformanceTest : public ::testing::Test {
 protected:
  // Helper to verify basic DnsRecord invariants
  void verifyRecord(const DnsRecord& dr, const std::string& sProvider) {
    SCOPED_TRACE("Provider: " + sProvider);
    EXPECT_FALSE(dr.sProviderRecordId.empty()) << "Record ID must not be empty";
    EXPECT_FALSE(dr.sName.empty()) << "Record name must not be empty";
    EXPECT_FALSE(dr.sType.empty()) << "Record type must not be empty";
    EXPECT_GT(dr.uTtl, 0u) << "TTL must be positive";
    EXPECT_FALSE(dr.sValue.empty()) << "Record value must not be empty";
  }
};

TEST_F(ProviderConformanceTest, PowerDnsARecord) {
  std::string sJson = R"({
    "name": "example.com.",
    "rrsets": [{
      "name": "www.example.com.",
      "type": "A",
      "ttl": 300,
      "records": [{"content": "1.2.3.4", "disabled": false}]
    }]
  })";
  auto vRecords = dns::providers::PowerDnsProvider::parseZoneResponse(sJson);
  ASSERT_EQ(vRecords.size(), 1u);
  verifyRecord(vRecords[0], "powerdns");
}

TEST_F(ProviderConformanceTest, CloudflareARecord) {
  std::string sJson = R"({
    "success": true,
    "result": [{
      "id": "cf-uuid-1",
      "name": "www.example.com",
      "type": "A",
      "content": "1.2.3.4",
      "ttl": 300,
      "proxied": false
    }],
    "result_info": {"page": 1, "total_pages": 1}
  })";
  auto vRecords = dns::providers::CloudflareProvider::parseRecordsResponse(sJson);
  ASSERT_EQ(vRecords.size(), 1u);
  verifyRecord(vRecords[0], "cloudflare");
}

TEST_F(ProviderConformanceTest, DigitalOceanARecord) {
  std::string sJson = R"({
    "domain_records": [{
      "id": 12345,
      "type": "A",
      "name": "www",
      "data": "1.2.3.4",
      "ttl": 300,
      "priority": null
    }],
    "links": {},
    "meta": {"total": 1}
  })";
  auto vRecords = dns::providers::DigitalOceanProvider::parseRecordsResponse(sJson, "example.com");
  ASSERT_EQ(vRecords.size(), 1u);
  verifyRecord(vRecords[0], "digitalocean");
}

// MX records across all providers
TEST_F(ProviderConformanceTest, AllProvidersMxPriority) {
  // PowerDNS
  {
    std::string sJson = R"({"name":"example.com.","rrsets":[{
      "name":"example.com.","type":"MX","ttl":3600,
      "records":[{"content":"10 mail.example.com.","disabled":false}]
    }]})";
    auto v = dns::providers::PowerDnsProvider::parseZoneResponse(sJson);
    ASSERT_EQ(v.size(), 1u);
    EXPECT_EQ(v[0].iPriority, 10);
    EXPECT_EQ(v[0].sValue, "mail.example.com.");
  }

  // Cloudflare
  {
    std::string sJson = R"({"success":true,"result":[{
      "id":"cf-mx","name":"example.com","type":"MX","content":"mail.example.com",
      "ttl":3600,"priority":10,"proxied":false
    }],"result_info":{"page":1,"total_pages":1}})";
    auto v = dns::providers::CloudflareProvider::parseRecordsResponse(sJson);
    ASSERT_EQ(v.size(), 1u);
    EXPECT_EQ(v[0].iPriority, 10);
    EXPECT_EQ(v[0].sValue, "mail.example.com");
  }

  // DigitalOcean
  {
    std::string sJson = R"({"domain_records":[{
      "id":100,"type":"MX","name":"@","data":"mail.example.com.",
      "ttl":3600,"priority":10
    }],"links":{},"meta":{"total":1}})";
    auto v = dns::providers::DigitalOceanProvider::parseRecordsResponse(sJson, "example.com");
    ASSERT_EQ(v.size(), 1u);
    EXPECT_EQ(v[0].iPriority, 10);
    EXPECT_EQ(v[0].sValue, "mail.example.com.");
  }
}
```

**Step 2: Run the conformance tests**

```bash
cmake --build build --parallel && build/tests/dns-tests --gtest_filter="ProviderConformance*"
```

**Step 3: Commit**

```bash
git add tests/unit/test_provider_conformance.cpp
git commit -m "test: add provider conformance test suite"
```

---

### Task 10: Multi-Provider Deployment Improvements

**Goal:** Refactor the deployment pipeline so that when a zone's view has multiple providers,
each provider receives only the diffs relevant to its own state — not a merged diff.

**Files:**
- Modify: `include/common/Types.hpp` (add `ProviderPreviewResult`)
- Modify: `include/core/DiffEngine.hpp` (add `previewPerProvider`, `fetchLiveRecordsPerProvider`)
- Modify: `src/core/DiffEngine.cpp`
- Modify: `src/core/DeploymentEngine.cpp` (per-provider diff/push)
- Modify: `src/api/routes/RecordRoutes.cpp` (update preview response)
- Modify: `ui/src/types/index.ts` (extend `PreviewResult`)
- Modify: `ui/src/views/DeploymentsView.vue` (show per-provider diffs)
- Test: `tests/unit/test_diff_engine.cpp` (add per-provider diff tests)

**Step 1: Add ProviderPreviewResult type**

In `include/common/Types.hpp`:

```cpp
/// Per-provider preview result for multi-provider deployments.
struct ProviderPreviewResult {
  int64_t iProviderId = 0;
  std::string sProviderName;
  std::string sProviderType;
  std::vector<RecordDiff> vDiffs;
  bool bHasDrift = false;
};
```

Update `PreviewResult` to include per-provider breakdown:

```cpp
struct PreviewResult {
  int64_t iZoneId = 0;
  std::string sZoneName;
  std::vector<RecordDiff> vDiffs;             // Merged diffs (backward compat)
  bool bHasDrift = false;
  std::chrono::system_clock::time_point tpGeneratedAt;
  std::vector<ProviderPreviewResult> vProviderPreviews;  // Per-provider breakdown
};
```

**Step 2: Implement fetchLiveRecordsPerProvider**

In `src/core/DiffEngine.cpp`, add a new method that returns a map of provider ID → records:

```cpp
std::map<int64_t, std::vector<common::DnsRecord>> DiffEngine::fetchLiveRecordsPerProvider(
    int64_t iZoneId) {
  auto oZone = _zrRepo.findById(iZoneId);
  if (!oZone) throw common::NotFoundError("ZONE_NOT_FOUND", ...);

  auto oView = _vrRepo.findWithProviders(oZone->iViewId);
  if (!oView) throw common::NotFoundError("VIEW_NOT_FOUND", ...);
  if (oView->vProviderIds.empty()) throw common::ValidationError("NO_PROVIDERS", ...);

  std::map<int64_t, std::vector<common::DnsRecord>> mResult;
  for (int64_t iProviderId : oView->vProviderIds) {
    auto oProvider = _prRepo.findById(iProviderId);
    if (!oProvider) continue;

    auto upProvider = dns::providers::ProviderFactory::create(
        oProvider->sType, oProvider->sApiEndpoint, oProvider->sDecryptedToken,
        oProvider->jConfig);

    try {
      mResult[iProviderId] = upProvider->listRecords(oZone->sName);
    } catch (const common::ProviderError& ex) {
      common::Logger::get()->error("Failed to list from provider '{}': {}",
                                    oProvider->sName, ex.what());
      throw;
    }
  }
  return mResult;
}
```

**Step 3: Update preview() to compute per-provider diffs**

Refactor `DiffEngine::preview()` to compute diffs per provider:

```cpp
common::PreviewResult DiffEngine::preview(int64_t iZoneId) {
  auto oZone = _zrRepo.findById(iZoneId);
  if (!oZone) throw common::NotFoundError(...);

  // Fetch desired records and expand templates
  auto vRecordRows = _rrRepo.listByZoneId(iZoneId);
  std::vector<common::DnsRecord> vDesired;
  for (const auto& row : vRecordRows) {
    common::DnsRecord dr;
    dr.sName = row.sName;
    dr.sType = row.sType;
    dr.uTtl = static_cast<uint32_t>(row.iTtl);
    dr.sValue = _veEngine.expand(row.sValueTemplate, iZoneId);
    dr.iPriority = row.iPriority;
    dr.jProviderMeta = row.jProviderMeta;
    vDesired.push_back(std::move(dr));
  }

  vDesired = filterRecordTypes(vDesired, oZone->bManageSoa, oZone->bManageNs);

  // Fetch live records per provider
  auto mLive = fetchLiveRecordsPerProvider(iZoneId);

  // Compute per-provider diffs
  common::PreviewResult pr;
  pr.iZoneId = iZoneId;
  pr.sZoneName = oZone->sName;

  for (auto& [iProviderId, vLive] : mLive) {
    vLive = filterRecordTypes(vLive, oZone->bManageSoa, oZone->bManageNs);

    auto vDiffs = computeDiff(vDesired, vLive);

    auto oProvider = _prRepo.findById(iProviderId);

    common::ProviderPreviewResult ppr;
    ppr.iProviderId = iProviderId;
    ppr.sProviderName = oProvider ? oProvider->sName : "unknown";
    ppr.sProviderType = oProvider ? oProvider->sType : "unknown";
    ppr.vDiffs = vDiffs;
    ppr.bHasDrift = std::any_of(vDiffs.begin(), vDiffs.end(),
                                 [](const auto& d) { return d.action == common::DiffAction::Drift; });
    pr.vProviderPreviews.push_back(std::move(ppr));

    // Merge into combined diffs for backward compat
    pr.vDiffs.insert(pr.vDiffs.end(), vDiffs.begin(), vDiffs.end());
  }

  pr.bHasDrift = std::any_of(pr.vDiffs.begin(), pr.vDiffs.end(),
                              [](const auto& d) { return d.action == common::DiffAction::Drift; });
  pr.tpGeneratedAt = std::chrono::system_clock::now();

  return pr;
}
```

> **Note:** The merged `vDiffs` may contain duplicates if the same diff applies to multiple
> providers. For the merged view, deduplicate by name+type+action. For push operations,
> always use the per-provider breakdown.

**Step 4: Update DeploymentEngine::push() for per-provider diffs**

Replace the current provider loop (lines 162-229) with per-provider diff computation:

```cpp
// Get zone and view with providers
auto oZone = _zrRepo.findById(iZoneId);
auto oView = _vrRepo.findWithProviders(oZone->iViewId);

// Use per-provider previews from the fresh preview result
for (const auto& ppr : prResult.vProviderPreviews) {
  auto oProvider = _prRepo.findById(ppr.iProviderId);
  if (!oProvider) continue;

  auto upProvider = dns::providers::ProviderFactory::create(
      oProvider->sType, oProvider->sApiEndpoint, oProvider->sDecryptedToken,
      oProvider->jConfig);

  for (const auto& diff : ppr.vDiffs) {
    // ... same switch/case as before, but operating on this provider's specific diffs
  }
}
```

**Step 5: Update preview API response**

In `src/api/routes/RecordRoutes.cpp`, extend the preview response to include per-provider
breakdown:

```cpp
// Add per-provider previews to response
json jProviders = json::array();
for (const auto& ppr : prResult.vProviderPreviews) {
  json jProvider = {
      {"provider_id", ppr.iProviderId},
      {"provider_name", ppr.sProviderName},
      {"provider_type", ppr.sProviderType},
      {"has_drift", ppr.bHasDrift},
      {"diffs", json::array()},
  };
  for (const auto& d : ppr.vDiffs) {
    jProvider["diffs"].push_back({
        {"action", /* same mapping */},
        {"name", d.sName},
        {"type", d.sType},
        {"source_value", d.sSourceValue},
        {"provider_value", d.sProviderValue},
        {"ttl", d.uTtl},
        {"priority", d.iPriority},
    });
  }
  jProviders.push_back(std::move(jProvider));
}
jResult["providers"] = jProviders;
```

**Step 6: Update UI types**

In `ui/src/types/index.ts`:

```typescript
export interface ProviderPreview {
  provider_id: number
  provider_name: string
  provider_type: string
  has_drift: boolean
  diffs: RecordDiff[]
}

export interface PreviewResult {
  zone_id: number
  zone_name: string
  has_drift: boolean
  diffs: RecordDiff[]
  providers?: ProviderPreview[]
}
```

**Step 7: Update DeploymentsView**

In `ui/src/views/DeploymentsView.vue`, add per-provider tabs or sections when
`preview.providers` is populated:

- If `providers.length === 1`, show flat diffs (same as current)
- If `providers.length > 1`, show tabbed view with one tab per provider

**Step 8: Write tests for per-provider diff**

In `tests/unit/test_diff_engine.cpp`:

```cpp
TEST(DiffEngineComputeTest, PerProviderDiffIndependent) {
  // Same desired records, different live records per provider
  std::vector<dns::common::DnsRecord> vDesired = {{
      .sName = "www.example.com", .sType = "A", .uTtl = 300, .sValue = "1.2.3.4",
  }};

  // Provider A has the record already
  std::vector<dns::common::DnsRecord> vLiveA = {{
      .sProviderRecordId = "a1", .sName = "www.example.com", .sType = "A",
      .uTtl = 300, .sValue = "1.2.3.4",
  }};

  // Provider B does not have the record
  std::vector<dns::common::DnsRecord> vLiveB = {};

  auto vDiffsA = dns::core::DiffEngine::computeDiff(vDesired, vLiveA);
  auto vDiffsB = dns::core::DiffEngine::computeDiff(vDesired, vLiveB);

  EXPECT_TRUE(vDiffsA.empty());      // No changes needed for provider A
  ASSERT_EQ(vDiffsB.size(), 1u);     // Add needed for provider B
  EXPECT_EQ(vDiffsB[0].action, dns::common::DiffAction::Add);
}
```

**Step 9: Run all tests**

```bash
cmake --build build --parallel && build/tests/dns-tests
```

**Step 10: Commit**

```bash
git add include/common/Types.hpp include/core/DiffEngine.hpp src/core/DiffEngine.cpp \
  src/core/DeploymentEngine.cpp src/api/routes/RecordRoutes.cpp \
  ui/src/types/index.ts ui/src/views/DeploymentsView.vue tests/unit/test_diff_engine.cpp
git commit -m "feat: per-provider diff and deployment for multi-provider zones"
```

---

### Task 11: Documentation Update

**Goal:** Update CLAUDE.md, ARCHITECTURE.md, and OpenAPI spec for Phase 10 completion.

**Files:**
- Modify: `CLAUDE.md` (Phase 10 complete, test counts, deliverables)
- Modify: `docs/ARCHITECTURE.md` (provider implementation details)
- Modify: `docs/openapi.yaml` (update preview response schema, add provider_meta)

**Step 1: Update CLAUDE.md**

Mark Phase 10 as complete with summary:

```markdown
### Phase 10 — Additional Providers ← COMPLETE

**Summary:** Cloudflare API v4 and DigitalOcean API v2 providers fully implemented. Provider-
specific metadata support (Cloudflare proxy toggle). Per-provider diff/deployment pipeline
for correct multi-provider zone management. Conformance test suite.

**Deliverables:**
- `src/providers/CloudflareProvider.cpp` — full Cloudflare API v4 client with zone ID caching
- `src/providers/DigitalOceanProvider.cpp` — full DigitalOcean API v2 client
- `include/common/Types.hpp` — `jProviderMeta` on DnsRecord, `ProviderPreviewResult` type
- `scripts/db/v004/001_add_provider_meta.sql` — provider_meta JSONB column on records
- `src/core/DiffEngine.cpp` — per-provider diff computation
- `src/core/DeploymentEngine.cpp` — per-provider push execution
- `ui/src/views/ZoneDetailView.vue` — Cloudflare proxy toggle and badge
- `ui/src/views/DeploymentsView.vue` — per-provider preview tabs

**Tests:** N new tests (Cloudflare parsing, DigitalOcean parsing, name conversion,
conformance suite, per-provider diff)
```

**Step 2: Update OpenAPI spec**

Add `provider_meta` to record schemas and `providers` array to preview response.

**Step 3: Commit**

```bash
git add CLAUDE.md docs/ARCHITECTURE.md docs/openapi.yaml
git commit -m "docs: update CLAUDE.md for Phase 10 completion"
```

---

## Summary

| Task | Component | New Tests |
|------|-----------|-----------|
| 1 | Provider metadata (DnsRecord + DB migration) | 2 |
| 2 | Cloudflare zone ID resolution | 3 |
| 3 | Cloudflare testConnectivity + listRecords | 6 |
| 4 | Cloudflare CRUD operations | 3 |
| 5 | Proxy metadata through diff/deploy pipeline | 1 |
| 6 | Cloudflare proxy UI | 0 (manual) |
| 7 | DigitalOcean testConnectivity + listRecords | 6 |
| 8 | DigitalOcean CRUD operations | 6 |
| 9 | Provider conformance test suite | 4 |
| 10 | Multi-provider deployment improvements | 1 |
| 11 | Documentation update | 0 |
| **Total** | | **~32** |

**Estimated new test count:** ~32 new tests, bringing total from 235 to ~267.
