# Phase 6 — PowerDNS Provider + Core Engines Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Connect the application to a real DNS provider (PowerDNS), implement variable template
expansion, and compute three-way diffs between desired state and live provider state.

**Architecture:** Bottom-up build order — VariableEngine first (no external dependencies beyond
DAL), then ProviderFactory + PowerDnsProvider (HTTP client needed), then DiffEngine (depends on
both), then HealthRoutes and main.cpp wiring. Each component is independently compilable and
testable. TDD throughout: write failing test → implement → verify → commit.

**Tech Stack:** C++20, cpp-httplib (new — HTTP client via FetchContent), nlohmann/json,
Google Test + Google Mock, libpqxx (existing DAL).

---

## Prerequisites

- Phases 1–5 complete (all 129 tests pass or skip)
- Build passes: `cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug && cmake --build build --parallel`
- PostgreSQL + `DNS_DB_URL` available for integration tests

---

## Task 1: Add cpp-httplib HTTP Client Dependency

PowerDnsProvider needs an HTTP client for outbound REST calls to the PowerDNS API. cpp-httplib is
header-only, MIT-licensed, and FetchContent-compatible — matching the project's existing pattern
for Crow.

**Files:**
- Modify: `CMakeLists.txt`
- Modify: `src/CMakeLists.txt`

### Step 1: Add FetchContent declaration

In `CMakeLists.txt`, after the Crow `FetchContent_MakeAvailable(Crow)` block (around line 28),
add:

```cmake
# cpp-httplib via FetchContent (HTTP client for provider REST calls)
FetchContent_Declare(httplib
  GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
  GIT_TAG        v0.18.7
  GIT_SHALLOW    TRUE
)
set(HTTPLIB_REQUIRE_OPENSSL ON CACHE BOOL "" FORCE)
set(HTTPLIB_COMPILE OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(httplib)
```

### Step 2: Link httplib to dns-core

In `src/CMakeLists.txt`, add `httplib::httplib` to the `target_link_libraries` list for dns-core:

```cmake
target_link_libraries(dns-core PUBLIC
  PkgConfig::LIBPQXX
  OpenSSL::SSL
  OpenSSL::Crypto
  nlohmann_json::nlohmann_json
  spdlog::spdlog
  PkgConfig::LIBGIT2
  Crow::Crow
  httplib::httplib
)
```

### Step 3: Build to verify

```bash
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel
```

Expected: Clean build, all existing tests still pass.

### Step 4: Commit

```bash
git add CMakeLists.txt src/CMakeLists.txt
git commit -m "build: add cpp-httplib via FetchContent for provider HTTP calls"
```

---

## Task 2: VariableEngine — listDependencies() (Pure Unit Tests)

`listDependencies()` is pure string parsing — no DB needed. This is the easiest entry point for
VariableEngine. The method scans a template string for `{{var_name}}` patterns and returns the
list of variable names found.

**Files:**
- Modify: `include/core/VariableEngine.hpp` — no changes needed yet (listDependencies has no deps)
- Modify: `src/core/VariableEngine.cpp` — implement `listDependencies()`
- Modify: `tests/unit/test_variable_engine.cpp` — replace placeholder

### Step 1: Write failing tests

Replace the placeholder in `tests/unit/test_variable_engine.cpp`:

```cpp
#include "core/VariableEngine.hpp"

#include <gtest/gtest.h>

#include <string>
#include <vector>

using dns::core::VariableEngine;

class VariableEngineListDepsTest : public ::testing::Test {
 protected:
  VariableEngine _ve;
};

TEST_F(VariableEngineListDepsTest, NoPlaceholders) {
  auto vDeps = _ve.listDependencies("192.168.1.1");
  EXPECT_TRUE(vDeps.empty());
}

TEST_F(VariableEngineListDepsTest, SinglePlaceholder) {
  auto vDeps = _ve.listDependencies("192.168.1.{{octet}}");
  ASSERT_EQ(vDeps.size(), 1u);
  EXPECT_EQ(vDeps[0], "octet");
}

TEST_F(VariableEngineListDepsTest, MultiplePlaceholders) {
  auto vDeps = _ve.listDependencies("{{prefix}}.example.{{suffix}}");
  ASSERT_EQ(vDeps.size(), 2u);
  EXPECT_EQ(vDeps[0], "prefix");
  EXPECT_EQ(vDeps[1], "suffix");
}

TEST_F(VariableEngineListDepsTest, DuplicatePlaceholders) {
  auto vDeps = _ve.listDependencies("{{x}}.{{x}}");
  ASSERT_EQ(vDeps.size(), 1u);
  EXPECT_EQ(vDeps[0], "x");
}

TEST_F(VariableEngineListDepsTest, EntireValueIsVariable) {
  auto vDeps = _ve.listDependencies("{{server_ip}}");
  ASSERT_EQ(vDeps.size(), 1u);
  EXPECT_EQ(vDeps[0], "server_ip");
}

TEST_F(VariableEngineListDepsTest, EmptyString) {
  auto vDeps = _ve.listDependencies("");
  EXPECT_TRUE(vDeps.empty());
}

TEST_F(VariableEngineListDepsTest, MalformedBracesIgnored) {
  auto vDeps = _ve.listDependencies("{not_a_var}");
  EXPECT_TRUE(vDeps.empty());
}

TEST_F(VariableEngineListDepsTest, UnderscoreAndDigitsInName) {
  auto vDeps = _ve.listDependencies("{{my_var_2}}");
  ASSERT_EQ(vDeps.size(), 1u);
  EXPECT_EQ(vDeps[0], "my_var_2");
}
```

### Step 2: Run tests to verify they fail

```bash
cmake --build build --parallel && build/tests/dns-tests --gtest_filter="VariableEngineListDeps*"
```

Expected: FAIL — `listDependencies()` throws `runtime_error("not implemented")`.

### Step 3: Implement listDependencies()

In `src/core/VariableEngine.cpp`, replace the `listDependencies` stub:

```cpp
#include "core/VariableEngine.hpp"

#include <algorithm>
#include <regex>
#include <stdexcept>
#include <string>
#include <vector>

namespace dns::core {

VariableEngine::VariableEngine() = default;
VariableEngine::~VariableEngine() = default;

std::string VariableEngine::expand(const std::string& /*sTmpl*/, int64_t /*iZoneId*/) const {
  throw std::runtime_error{"not implemented"};
}

bool VariableEngine::validate(const std::string& /*sTmpl*/, int64_t /*iZoneId*/) const {
  throw std::runtime_error{"not implemented"};
}

std::vector<std::string> VariableEngine::listDependencies(const std::string& sTmpl) const {
  static const std::regex reVar(R"(\{\{([A-Za-z0-9_]+)\}\})");
  std::vector<std::string> vDeps;

  auto itBegin = std::sregex_iterator(sTmpl.begin(), sTmpl.end(), reVar);
  auto itEnd = std::sregex_iterator();

  for (auto it = itBegin; it != itEnd; ++it) {
    std::string sName = (*it)[1].str();
    if (std::find(vDeps.begin(), vDeps.end(), sName) == vDeps.end()) {
      vDeps.push_back(std::move(sName));
    }
  }

  return vDeps;
}

}  // namespace dns::core
```

### Step 4: Run tests to verify they pass

```bash
cmake --build build --parallel && build/tests/dns-tests --gtest_filter="VariableEngineListDeps*"
```

Expected: All 8 tests PASS.

### Step 5: Commit

```bash
git add src/core/VariableEngine.cpp tests/unit/test_variable_engine.cpp
git commit -m "feat(core): implement VariableEngine::listDependencies with TDD"
```

---

## Task 3: VariableEngine — expand() and validate()

These methods need `VariableRepository` to look up variable values. This requires updating the
header to inject the repository dependency, and writing integration tests that need `DNS_DB_URL`.

**Files:**
- Modify: `include/core/VariableEngine.hpp` — add `VariableRepository&` constructor param
- Modify: `src/core/VariableEngine.cpp` — implement `expand()` and `validate()`
- Modify: `tests/unit/test_variable_engine.cpp` — update fixture for new constructor
- Create: `tests/integration/test_variable_engine_expand.cpp` — integration tests

**Algorithm (from ARCHITECTURE.md §4.2.1):**
```
1. Scan value for pattern \{\{([A-Za-z0-9_]+)\}\}
2. For each match token:
   a. Look up in zone-scoped variables WHERE zone_id = ?
   b. If not found, look up in global variables WHERE zone_id IS NULL
   c. If not found → throw UnresolvedVariableError
   d. Replace placeholder with the literal resolved value (no further expansion)
3. Return fully expanded string
```

Variable values are flat literals — no nested `{{var}}` expansion.

### Step 1: Update VariableEngine header

Replace `include/core/VariableEngine.hpp`:

```cpp
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace dns::dal {
class VariableRepository;
}

namespace dns::core {

/// Tokenizes and expands {{var}} placeholders in record templates.
/// Class abbreviation: ve
class VariableEngine {
 public:
  /// Construct without a repository — only listDependencies() is usable.
  VariableEngine();

  /// Construct with a repository — all methods are usable.
  explicit VariableEngine(dns::dal::VariableRepository& varRepo);

  ~VariableEngine();

  /// Expand all {{var}} placeholders in sTmpl using variables for iZoneId.
  /// Zone-scoped variables take precedence over global.
  /// Throws UnresolvedVariableError if any variable cannot be resolved.
  std::string expand(const std::string& sTmpl, int64_t iZoneId) const;

  /// Returns true if all {{var}} placeholders in sTmpl can be resolved for iZoneId.
  bool validate(const std::string& sTmpl, int64_t iZoneId) const;

  /// Extract variable names from {{var}} placeholders. No DB access needed.
  std::vector<std::string> listDependencies(const std::string& sTmpl) const;

 private:
  dns::dal::VariableRepository* _pVarRepo = nullptr;
};

}  // namespace dns::core
```

Note: Two constructors — the no-arg constructor keeps `listDependencies()` usable in contexts
where no repository is available (e.g., unit tests, validation-only scenarios). The `expand()` and
`validate()` methods check `_pVarRepo != nullptr` and throw if missing.

### Step 2: Update unit test fixture

In `tests/unit/test_variable_engine.cpp`, the `VariableEngineListDepsTest` fixture uses
`VariableEngine _ve;` which calls the no-arg constructor. No changes needed — it still compiles.

### Step 3: Write failing integration tests

Create `tests/integration/test_variable_engine_expand.cpp`:

```cpp
#include "core/VariableEngine.hpp"

#include <gtest/gtest.h>

#include <cstdlib>
#include <memory>
#include <string>

#include "common/Errors.hpp"
#include "common/Logger.hpp"
#include "dal/ConnectionPool.hpp"
#include "dal/VariableRepository.hpp"
#include "dal/ZoneRepository.hpp"
#include "dal/ViewRepository.hpp"

using dns::core::VariableEngine;
using dns::dal::ConnectionPool;
using dns::dal::VariableRepository;
using dns::dal::ViewRepository;
using dns::dal::ZoneRepository;

namespace {
std::string getDbUrl() {
  const char* pUrl = std::getenv("DNS_DB_URL");
  return pUrl ? std::string(pUrl) : std::string{};
}
}  // namespace

class VariableEngineExpandTest : public ::testing::Test {
 protected:
  void SetUp() override {
    _sDbUrl = getDbUrl();
    if (_sDbUrl.empty()) {
      GTEST_SKIP() << "DNS_DB_URL not set — skipping integration test";
    }
    dns::common::Logger::init("warn");
    _cpPool = std::make_unique<ConnectionPool>(_sDbUrl, 2);
    _varRepo = std::make_unique<VariableRepository>(*_cpPool);
    _vrRepo = std::make_unique<ViewRepository>(*_cpPool);
    _zrRepo = std::make_unique<ZoneRepository>(*_cpPool);
    _ve = std::make_unique<VariableEngine>(*_varRepo);

    // Clean test data (order matters for FK constraints)
    auto cg = _cpPool->checkout();
    pqxx::work txn(*cg);
    txn.exec("DELETE FROM variables");
    txn.exec("DELETE FROM records");
    txn.exec("DELETE FROM zones");
    txn.exec("DELETE FROM view_providers");
    txn.exec("DELETE FROM views");
    txn.commit();

    // Create a test view and zone
    _iViewId = _vrRepo->create("test-view", "Test view for variable engine");
    _iZoneId = _zrRepo->create("example.com", _iViewId, std::nullopt);
  }

  std::string _sDbUrl;
  std::unique_ptr<ConnectionPool> _cpPool;
  std::unique_ptr<VariableRepository> _varRepo;
  std::unique_ptr<ViewRepository> _vrRepo;
  std::unique_ptr<ZoneRepository> _zrRepo;
  std::unique_ptr<VariableEngine> _ve;
  int64_t _iViewId = 0;
  int64_t _iZoneId = 0;
};

TEST_F(VariableEngineExpandTest, NoPlaceholders) {
  std::string sResult = _ve->expand("192.168.1.1", _iZoneId);
  EXPECT_EQ(sResult, "192.168.1.1");
}

TEST_F(VariableEngineExpandTest, ExpandGlobalVariable) {
  _varRepo->create("server_ip", "10.0.0.1", "ipv4", "global", std::nullopt);
  std::string sResult = _ve->expand("{{server_ip}}", _iZoneId);
  EXPECT_EQ(sResult, "10.0.0.1");
}

TEST_F(VariableEngineExpandTest, ExpandZoneScopedVariable) {
  _varRepo->create("octet", "42", "string", "zone", _iZoneId);
  std::string sResult = _ve->expand("192.168.1.{{octet}}", _iZoneId);
  EXPECT_EQ(sResult, "192.168.1.42");
}

TEST_F(VariableEngineExpandTest, ZoneScopedTakesPrecedenceOverGlobal) {
  _varRepo->create("ip", "10.0.0.1", "ipv4", "global", std::nullopt);
  _varRepo->create("ip", "10.0.0.99", "ipv4", "zone", _iZoneId);
  std::string sResult = _ve->expand("{{ip}}", _iZoneId);
  EXPECT_EQ(sResult, "10.0.0.99");
}

TEST_F(VariableEngineExpandTest, MultipleVariables) {
  _varRepo->create("prefix", "10.0", "string", "global", std::nullopt);
  _varRepo->create("suffix", "1.42", "string", "zone", _iZoneId);
  std::string sResult = _ve->expand("{{prefix}}.{{suffix}}", _iZoneId);
  EXPECT_EQ(sResult, "10.0.1.42");
}

TEST_F(VariableEngineExpandTest, UnresolvedVariableThrows) {
  EXPECT_THROW(_ve->expand("{{nonexistent}}", _iZoneId),
               dns::common::UnresolvedVariableError);
}

TEST_F(VariableEngineExpandTest, ValidateReturnsTrueWhenAllResolved) {
  _varRepo->create("host", "web01", "string", "global", std::nullopt);
  EXPECT_TRUE(_ve->validate("{{host}}.example.com", _iZoneId));
}

TEST_F(VariableEngineExpandTest, ValidateReturnsFalseWhenUnresolved) {
  EXPECT_FALSE(_ve->validate("{{missing}}.example.com", _iZoneId));
}

TEST_F(VariableEngineExpandTest, EmptyTemplateExpandsToEmpty) {
  std::string sResult = _ve->expand("", _iZoneId);
  EXPECT_EQ(sResult, "");
}
```

### Step 4: Run tests to verify they fail

```bash
cmake --build build --parallel && build/tests/dns-tests --gtest_filter="VariableEngineExpand*"
```

Expected: FAIL — `expand()` throws `runtime_error("not implemented")`.

### Step 5: Implement expand() and validate()

Update `src/core/VariableEngine.cpp` — replace the expand and validate stubs:

```cpp
#include "core/VariableEngine.hpp"

#include <algorithm>
#include <regex>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#include "common/Errors.hpp"
#include "dal/VariableRepository.hpp"

namespace dns::core {

VariableEngine::VariableEngine() = default;

VariableEngine::VariableEngine(dns::dal::VariableRepository& varRepo)
    : _pVarRepo(&varRepo) {}

VariableEngine::~VariableEngine() = default;

std::string VariableEngine::expand(const std::string& sTmpl, int64_t iZoneId) const {
  if (!_pVarRepo) {
    throw std::runtime_error("VariableEngine: no VariableRepository injected");
  }

  auto vDeps = listDependencies(sTmpl);
  if (vDeps.empty()) return sTmpl;

  // Fetch all variables for this zone (zone-scoped + global)
  auto vRows = _pVarRepo->listByZoneId(iZoneId);

  // Build lookup map: zone-scoped vars shadow global vars
  std::unordered_map<std::string, std::string> mVars;
  for (const auto& row : vRows) {
    if (row.sScope == "global") {
      mVars.emplace(row.sName, row.sValue);  // emplace won't overwrite
    }
  }
  for (const auto& row : vRows) {
    if (row.sScope == "zone") {
      mVars[row.sName] = row.sValue;  // overwrites global
    }
  }

  // Replace all {{var}} placeholders
  static const std::regex reVar(R"(\{\{([A-Za-z0-9_]+)\}\})");
  std::string sResult;
  auto itBegin = std::sregex_iterator(sTmpl.begin(), sTmpl.end(), reVar);
  auto itEnd = std::sregex_iterator();

  size_t iLastPos = 0;
  for (auto it = itBegin; it != itEnd; ++it) {
    sResult.append(sTmpl, iLastPos, static_cast<size_t>(it->position()) - iLastPos);
    std::string sVarName = (*it)[1].str();
    auto found = mVars.find(sVarName);
    if (found == mVars.end()) {
      throw common::UnresolvedVariableError(
          "UNDEFINED_VARIABLE",
          "Variable '" + sVarName + "' not found for zone " + std::to_string(iZoneId));
    }
    sResult.append(found->second);
    iLastPos = static_cast<size_t>(it->position() + it->length());
  }
  sResult.append(sTmpl, iLastPos);

  return sResult;
}

bool VariableEngine::validate(const std::string& sTmpl, int64_t iZoneId) const {
  if (!_pVarRepo) {
    throw std::runtime_error("VariableEngine: no VariableRepository injected");
  }

  auto vDeps = listDependencies(sTmpl);
  if (vDeps.empty()) return true;

  auto vRows = _pVarRepo->listByZoneId(iZoneId);
  std::unordered_map<std::string, bool> mExists;
  for (const auto& row : vRows) {
    mExists[row.sName] = true;
  }

  for (const auto& sDep : vDeps) {
    if (mExists.find(sDep) == mExists.end()) return false;
  }
  return true;
}

std::vector<std::string> VariableEngine::listDependencies(const std::string& sTmpl) const {
  static const std::regex reVar(R"(\{\{([A-Za-z0-9_]+)\}\})");
  std::vector<std::string> vDeps;

  auto itBegin = std::sregex_iterator(sTmpl.begin(), sTmpl.end(), reVar);
  auto itEnd = std::sregex_iterator();

  for (auto it = itBegin; it != itEnd; ++it) {
    std::string sName = (*it)[1].str();
    if (std::find(vDeps.begin(), vDeps.end(), sName) == vDeps.end()) {
      vDeps.push_back(std::move(sName));
    }
  }

  return vDeps;
}

}  // namespace dns::core
```

### Step 6: Run tests to verify they pass

```bash
cmake --build build --parallel && build/tests/dns-tests --gtest_filter="VariableEngine*"
```

Expected: Unit tests PASS. Integration tests PASS (if `DNS_DB_URL` is set) or SKIP.

### Step 7: Commit

```bash
git add include/core/VariableEngine.hpp src/core/VariableEngine.cpp \
  tests/integration/test_variable_engine_expand.cpp
git commit -m "feat(core): implement VariableEngine expand/validate with zone-scoped precedence"
```

---

## Task 4: ProviderFactory

Trivial factory — switch on `sType` string to instantiate the correct `IProvider` subclass.
Phase 6 only wires `powerdns`; the others throw `ValidationError`.

**Files:**
- Modify: `src/providers/ProviderFactory.cpp` — implement factory logic
- Modify: `tests/unit/test_provider_factory.cpp` — replace placeholder

### Step 1: Write failing tests

Replace `tests/unit/test_provider_factory.cpp`:

```cpp
#include "providers/ProviderFactory.hpp"

#include <gtest/gtest.h>

#include <memory>
#include <string>

#include "common/Errors.hpp"
#include "providers/PowerDnsProvider.hpp"

using dns::providers::ProviderFactory;

TEST(ProviderFactoryTest, CreatesPowerDnsProvider) {
  auto upProvider = ProviderFactory::create("powerdns", "http://localhost:8081", "test-key");
  ASSERT_NE(upProvider, nullptr);
  EXPECT_EQ(upProvider->name(), "powerdns");
}

TEST(ProviderFactoryTest, UnknownTypeThrows) {
  EXPECT_THROW(ProviderFactory::create("unknown", "http://localhost", "key"),
               dns::common::ValidationError);
}

TEST(ProviderFactoryTest, CloudflareNotYetImplemented) {
  EXPECT_THROW(ProviderFactory::create("cloudflare", "https://api.cloudflare.com", "key"),
               dns::common::ValidationError);
}

TEST(ProviderFactoryTest, DigitalOceanNotYetImplemented) {
  EXPECT_THROW(ProviderFactory::create("digitalocean", "https://api.digitalocean.com", "key"),
               dns::common::ValidationError);
}
```

### Step 2: Run tests to verify they fail

```bash
cmake --build build --parallel && build/tests/dns-tests --gtest_filter="ProviderFactory*"
```

Expected: FAIL — `create()` throws `runtime_error("not implemented")`.

### Step 3: Implement ProviderFactory

Replace `src/providers/ProviderFactory.cpp`:

```cpp
#include "providers/ProviderFactory.hpp"

#include <memory>
#include <string>

#include "common/Errors.hpp"
#include "providers/PowerDnsProvider.hpp"

namespace dns::providers {

std::unique_ptr<IProvider> ProviderFactory::create(const std::string& sType,
                                                   const std::string& sApiEndpoint,
                                                   const std::string& sDecryptedToken) {
  if (sType == "powerdns") {
    return std::make_unique<PowerDnsProvider>(sApiEndpoint, sDecryptedToken);
  }
  if (sType == "cloudflare" || sType == "digitalocean") {
    throw common::ValidationError(
        "PROVIDER_NOT_IMPLEMENTED",
        "Provider type '" + sType + "' is not yet implemented");
  }
  throw common::ValidationError(
      "UNKNOWN_PROVIDER_TYPE",
      "Unknown provider type: '" + sType + "'");
}

}  // namespace dns::providers
```

### Step 4: Run tests to verify they pass

```bash
cmake --build build --parallel && build/tests/dns-tests --gtest_filter="ProviderFactory*"
```

Expected: All 4 tests PASS.

### Step 5: Commit

```bash
git add src/providers/ProviderFactory.cpp tests/unit/test_provider_factory.cpp
git commit -m "feat(providers): implement ProviderFactory with PowerDNS support"
```

---

## Task 5: PowerDnsProvider — HTTP Helpers and testConnectivity()

Implement the PowerDNS provider's HTTP communication layer and connectivity test. The PowerDNS
Authoritative Server REST API v1 uses:
- Base URL: `{api_endpoint}/api/v1/servers/localhost`
- Auth header: `X-API-Key: {token}`
- Content-Type: `application/json`

**Key design note:** PowerDNS uses rrsets (Resource Record Sets) — records grouped by name+type.
Our `DnsRecord` model is per-record. The provider must bridge this gap:
- `listRecords()` flattens rrsets → individual `DnsRecord` entries
- `createRecord()`/`updateRecord()` use PATCH with `changetype: "REPLACE"` on the full rrset
- `deleteRecord()` uses PATCH to remove a record from its rrset

**Synthetic provider_record_id format:** `{name}/{type}/{value}` — uniquely identifies a record
within PowerDNS (which has no individual record IDs).

**Files:**
- Modify: `include/providers/PowerDnsProvider.hpp` — add private helpers
- Modify: `src/providers/PowerDnsProvider.cpp` — full implementation
- Create: `tests/unit/test_powerdns_provider.cpp` — unit tests for JSON parsing

### Step 1: Update PowerDnsProvider header

Replace `include/providers/PowerDnsProvider.hpp`:

```cpp
#pragma once

#include <memory>
#include <string>
#include <vector>

#include "providers/IProvider.hpp"

namespace httplib {
class Client;
}

namespace dns::providers {

/// PowerDNS REST API v1 provider implementation.
/// Class abbreviation: pdns
class PowerDnsProvider : public IProvider {
 public:
  PowerDnsProvider(std::string sApiEndpoint, std::string sToken);
  ~PowerDnsProvider() override;

  std::string name() const override;
  common::HealthStatus testConnectivity() override;
  std::vector<common::DnsRecord> listRecords(const std::string& sZoneName) override;
  common::PushResult createRecord(const std::string& sZoneName,
                                  const common::DnsRecord& drRecord) override;
  common::PushResult updateRecord(const std::string& sZoneName,
                                  const common::DnsRecord& drRecord) override;
  bool deleteRecord(const std::string& sZoneName,
                    const std::string& sProviderRecordId) override;

  /// Parse a PowerDNS zone JSON response into DnsRecord entries.
  /// Public for unit testing; called internally by listRecords().
  static std::vector<common::DnsRecord> parseZoneResponse(const std::string& sJson);

  /// Build a synthetic provider_record_id: "name/type/value".
  static std::string makeRecordId(const std::string& sName, const std::string& sType,
                                  const std::string& sValue);

  /// Parse a synthetic provider_record_id into (name, type, value).
  /// Returns false if the format is invalid.
  static bool parseRecordId(const std::string& sId, std::string& sName,
                            std::string& sType, std::string& sValue);

 private:
  std::string _sApiEndpoint;
  std::string _sToken;
  std::unique_ptr<httplib::Client> _upClient;

  /// Ensure zone name ends with a dot (PowerDNS requirement).
  static std::string canonicalZone(const std::string& sZoneName);
};

}  // namespace dns::providers
```

### Step 2: Write failing unit tests for JSON parsing

Create `tests/unit/test_powerdns_provider.cpp`:

```cpp
#include "providers/PowerDnsProvider.hpp"

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "common/Types.hpp"

using dns::common::DnsRecord;
using dns::providers::PowerDnsProvider;

// --- parseZoneResponse tests ---

TEST(PowerDnsParseTest, EmptyRrsets) {
  std::string sJson = R"({"name":"example.com.","rrsets":[]})";
  auto vRecords = PowerDnsProvider::parseZoneResponse(sJson);
  EXPECT_TRUE(vRecords.empty());
}

TEST(PowerDnsParseTest, SingleARecord) {
  std::string sJson = R"({
    "name": "example.com.",
    "rrsets": [{
      "name": "www.example.com.",
      "type": "A",
      "ttl": 300,
      "records": [{"content": "192.168.1.1", "disabled": false}]
    }]
  })";
  auto vRecords = PowerDnsProvider::parseZoneResponse(sJson);
  ASSERT_EQ(vRecords.size(), 1u);
  EXPECT_EQ(vRecords[0].sName, "www.example.com.");
  EXPECT_EQ(vRecords[0].sType, "A");
  EXPECT_EQ(vRecords[0].uTtl, 300u);
  EXPECT_EQ(vRecords[0].sValue, "192.168.1.1");
  EXPECT_EQ(vRecords[0].sProviderRecordId, "www.example.com./A/192.168.1.1");
}

TEST(PowerDnsParseTest, MultipleRecordsInRrset) {
  std::string sJson = R"({
    "name": "example.com.",
    "rrsets": [{
      "name": "example.com.",
      "type": "NS",
      "ttl": 3600,
      "records": [
        {"content": "ns1.example.com.", "disabled": false},
        {"content": "ns2.example.com.", "disabled": false}
      ]
    }]
  })";
  auto vRecords = PowerDnsProvider::parseZoneResponse(sJson);
  ASSERT_EQ(vRecords.size(), 2u);
  EXPECT_EQ(vRecords[0].sValue, "ns1.example.com.");
  EXPECT_EQ(vRecords[1].sValue, "ns2.example.com.");
}

TEST(PowerDnsParseTest, DisabledRecordsSkipped) {
  std::string sJson = R"({
    "name": "example.com.",
    "rrsets": [{
      "name": "www.example.com.",
      "type": "A",
      "ttl": 300,
      "records": [
        {"content": "192.168.1.1", "disabled": false},
        {"content": "192.168.1.2", "disabled": true}
      ]
    }]
  })";
  auto vRecords = PowerDnsProvider::parseZoneResponse(sJson);
  ASSERT_EQ(vRecords.size(), 1u);
  EXPECT_EQ(vRecords[0].sValue, "192.168.1.1");
}

TEST(PowerDnsParseTest, MxRecordWithPriority) {
  std::string sJson = R"({
    "name": "example.com.",
    "rrsets": [{
      "name": "example.com.",
      "type": "MX",
      "ttl": 3600,
      "records": [{"content": "10 mail.example.com.", "disabled": false}]
    }]
  })";
  auto vRecords = PowerDnsProvider::parseZoneResponse(sJson);
  ASSERT_EQ(vRecords.size(), 1u);
  EXPECT_EQ(vRecords[0].sType, "MX");
  EXPECT_EQ(vRecords[0].iPriority, 10);
  EXPECT_EQ(vRecords[0].sValue, "mail.example.com.");
}

TEST(PowerDnsParseTest, SoaRecordIncluded) {
  std::string sJson = R"({
    "name": "example.com.",
    "rrsets": [{
      "name": "example.com.",
      "type": "SOA",
      "ttl": 3600,
      "records": [{"content": "ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400", "disabled": false}]
    }]
  })";
  auto vRecords = PowerDnsProvider::parseZoneResponse(sJson);
  ASSERT_EQ(vRecords.size(), 1u);
  EXPECT_EQ(vRecords[0].sType, "SOA");
}

// --- makeRecordId / parseRecordId tests ---

TEST(PowerDnsRecordIdTest, MakeAndParse) {
  std::string sId = PowerDnsProvider::makeRecordId("www.example.com.", "A", "1.2.3.4");
  EXPECT_EQ(sId, "www.example.com./A/1.2.3.4");

  std::string sName, sType, sValue;
  ASSERT_TRUE(PowerDnsProvider::parseRecordId(sId, sName, sType, sValue));
  EXPECT_EQ(sName, "www.example.com.");
  EXPECT_EQ(sType, "A");
  EXPECT_EQ(sValue, "1.2.3.4");
}

TEST(PowerDnsRecordIdTest, InvalidFormat) {
  std::string sName, sType, sValue;
  EXPECT_FALSE(PowerDnsProvider::parseRecordId("invalid", sName, sType, sValue));
  EXPECT_FALSE(PowerDnsProvider::parseRecordId("only/one", sName, sType, sValue));
}
```

### Step 3: Run tests to verify they fail

```bash
cmake --build build --parallel && build/tests/dns-tests --gtest_filter="PowerDns*"
```

Expected: FAIL — methods not yet implemented.

### Step 4: Implement PowerDnsProvider

Replace `src/providers/PowerDnsProvider.cpp`:

```cpp
#include "providers/PowerDnsProvider.hpp"

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

PowerDnsProvider::PowerDnsProvider(std::string sApiEndpoint, std::string sToken)
    : _sApiEndpoint(std::move(sApiEndpoint)),
      _sToken(std::move(sToken)),
      _upClient(std::make_unique<httplib::Client>(_sApiEndpoint)) {
  _upClient->set_default_headers({{"X-API-Key", _sToken}});
  _upClient->set_connection_timeout(5);
  _upClient->set_read_timeout(10);
}

PowerDnsProvider::~PowerDnsProvider() = default;

std::string PowerDnsProvider::name() const { return "powerdns"; }

std::string PowerDnsProvider::canonicalZone(const std::string& sZoneName) {
  if (sZoneName.empty() || sZoneName.back() == '.') return sZoneName;
  return sZoneName + ".";
}

std::string PowerDnsProvider::makeRecordId(const std::string& sName, const std::string& sType,
                                           const std::string& sValue) {
  return sName + "/" + sType + "/" + sValue;
}

bool PowerDnsProvider::parseRecordId(const std::string& sId, std::string& sName,
                                     std::string& sType, std::string& sValue) {
  auto iFirst = sId.find('/');
  if (iFirst == std::string::npos) return false;
  auto iSecond = sId.find('/', iFirst + 1);
  if (iSecond == std::string::npos) return false;

  sName = sId.substr(0, iFirst);
  sType = sId.substr(iFirst + 1, iSecond - iFirst - 1);
  sValue = sId.substr(iSecond + 1);
  return true;
}

common::HealthStatus PowerDnsProvider::testConnectivity() {
  auto spLog = common::Logger::get();
  try {
    auto res = _upClient->Get("/api/v1/servers");
    if (!res) {
      spLog->warn("PowerDNS {}: connection failed", _sApiEndpoint);
      return common::HealthStatus::Unreachable;
    }
    if (res->status == 200) {
      return common::HealthStatus::Ok;
    }
    spLog->warn("PowerDNS {}: unexpected status {}", _sApiEndpoint, res->status);
    return common::HealthStatus::Degraded;
  } catch (const std::exception& ex) {
    spLog->error("PowerDNS {}: connectivity test failed: {}", _sApiEndpoint, ex.what());
    return common::HealthStatus::Unreachable;
  }
}

std::vector<common::DnsRecord> PowerDnsProvider::parseZoneResponse(const std::string& sJson) {
  std::vector<common::DnsRecord> vRecords;
  auto jZone = json::parse(sJson);
  auto& jRrsets = jZone.at("rrsets");

  for (auto& jRrset : jRrsets) {
    std::string sName = jRrset.at("name").get<std::string>();
    std::string sType = jRrset.at("type").get<std::string>();
    uint32_t uTtl = jRrset.at("ttl").get<uint32_t>();

    for (auto& jRecord : jRrset.at("records")) {
      if (jRecord.value("disabled", false)) continue;

      std::string sContent = jRecord.at("content").get<std::string>();
      int iPriority = 0;

      // MX and SRV records: priority is the first token in content
      if (sType == "MX" || sType == "SRV") {
        auto iSpace = sContent.find(' ');
        if (iSpace != std::string::npos) {
          iPriority = std::stoi(sContent.substr(0, iSpace));
          sContent = sContent.substr(iSpace + 1);
        }
      }

      common::DnsRecord dr;
      dr.sProviderRecordId = makeRecordId(sName, sType, jRecord.at("content").get<std::string>());
      dr.sName = sName;
      dr.sType = sType;
      dr.uTtl = uTtl;
      dr.sValue = sContent;
      dr.iPriority = iPriority;
      vRecords.push_back(std::move(dr));
    }
  }

  return vRecords;
}

std::vector<common::DnsRecord> PowerDnsProvider::listRecords(const std::string& sZoneName) {
  auto spLog = common::Logger::get();
  std::string sCanonical = canonicalZone(sZoneName);
  std::string sPath = "/api/v1/servers/localhost/zones/" + sCanonical;

  auto res = _upClient->Get(sPath);
  if (!res) {
    throw common::ProviderError(
        "POWERDNS_UNREACHABLE",
        "Failed to connect to PowerDNS at " + _sApiEndpoint);
  }
  if (res->status != 200) {
    throw common::ProviderError(
        "POWERDNS_LIST_FAILED",
        "PowerDNS returned status " + std::to_string(res->status) +
            " for zone " + sCanonical);
  }

  spLog->debug("PowerDNS: listed records for zone {}", sCanonical);
  return parseZoneResponse(res->body);
}

common::PushResult PowerDnsProvider::createRecord(const std::string& sZoneName,
                                                  const common::DnsRecord& drRecord) {
  auto spLog = common::Logger::get();
  std::string sCanonical = canonicalZone(sZoneName);
  std::string sPath = "/api/v1/servers/localhost/zones/" + sCanonical;

  // First, fetch existing records for this name+type to build the full rrset
  std::vector<common::DnsRecord> vExisting;
  try {
    auto vAll = listRecords(sZoneName);
    for (auto& dr : vAll) {
      if (dr.sName == drRecord.sName && dr.sType == drRecord.sType) {
        vExisting.push_back(std::move(dr));
      }
    }
  } catch (const common::ProviderError&) {
    // Zone may not have any records yet — proceed with just the new record
  }

  // Build content string (MX/SRV prefix priority)
  std::string sContent = drRecord.sValue;
  if ((drRecord.sType == "MX" || drRecord.sType == "SRV") && drRecord.iPriority > 0) {
    sContent = std::to_string(drRecord.iPriority) + " " + drRecord.sValue;
  }

  // Build records array: existing + new
  json jRecords = json::array();
  for (const auto& dr : vExisting) {
    std::string sExistingContent = dr.sValue;
    if ((dr.sType == "MX" || dr.sType == "SRV") && dr.iPriority > 0) {
      sExistingContent = std::to_string(dr.iPriority) + " " + dr.sValue;
    }
    jRecords.push_back({{"content", sExistingContent}, {"disabled", false}});
  }
  jRecords.push_back({{"content", sContent}, {"disabled", false}});

  json jBody = {
      {"rrsets",
       {{{"name", drRecord.sName},
         {"type", drRecord.sType},
         {"ttl", drRecord.uTtl},
         {"changetype", "REPLACE"},
         {"records", jRecords}}}}};

  auto res = _upClient->Patch(sPath, jBody.dump(), "application/json");
  if (!res) {
    return {false, "", "Failed to connect to PowerDNS"};
  }
  if (res->status != 204 && res->status != 200) {
    return {false, "", "PowerDNS returned status " + std::to_string(res->status)};
  }

  std::string sNewId = makeRecordId(drRecord.sName, drRecord.sType, sContent);
  spLog->info("PowerDNS: created record {} in zone {}", sNewId, sCanonical);
  return {true, sNewId, ""};
}

common::PushResult PowerDnsProvider::updateRecord(const std::string& sZoneName,
                                                  const common::DnsRecord& drRecord) {
  // For PowerDNS, update == replace the entire rrset containing this record.
  // The drRecord contains the NEW value; sProviderRecordId identifies the OLD record.
  auto spLog = common::Logger::get();
  std::string sCanonical = canonicalZone(sZoneName);
  std::string sPath = "/api/v1/servers/localhost/zones/" + sCanonical;

  std::string sOldName, sOldType, sOldValue;
  if (!parseRecordId(drRecord.sProviderRecordId, sOldName, sOldType, sOldValue)) {
    return {false, "", "Invalid provider_record_id format"};
  }

  // Fetch existing rrset for this name+type
  auto vAll = listRecords(sZoneName);
  json jRecords = json::array();
  for (const auto& dr : vAll) {
    if (dr.sName != sOldName || dr.sType != sOldType) continue;

    std::string sContent;
    // Check if this is the record being updated
    std::string sCheckName, sCheckType, sCheckValue;
    parseRecordId(dr.sProviderRecordId, sCheckName, sCheckType, sCheckValue);
    if (sCheckValue == sOldValue) {
      // This is the record to update — use new value
      sContent = drRecord.sValue;
      if ((drRecord.sType == "MX" || drRecord.sType == "SRV") && drRecord.iPriority > 0) {
        sContent = std::to_string(drRecord.iPriority) + " " + drRecord.sValue;
      }
    } else {
      // Keep existing record as-is
      sContent = dr.sValue;
      if ((dr.sType == "MX" || dr.sType == "SRV") && dr.iPriority > 0) {
        sContent = std::to_string(dr.iPriority) + " " + dr.sValue;
      }
    }
    jRecords.push_back({{"content", sContent}, {"disabled", false}});
  }

  json jBody = {
      {"rrsets",
       {{{"name", sOldName},
         {"type", sOldType},
         {"ttl", drRecord.uTtl},
         {"changetype", "REPLACE"},
         {"records", jRecords}}}}};

  auto res = _upClient->Patch(sPath, jBody.dump(), "application/json");
  if (!res) {
    return {false, "", "Failed to connect to PowerDNS"};
  }
  if (res->status != 204 && res->status != 200) {
    return {false, "", "PowerDNS returned status " + std::to_string(res->status)};
  }

  std::string sNewContent = drRecord.sValue;
  if ((drRecord.sType == "MX" || drRecord.sType == "SRV") && drRecord.iPriority > 0) {
    sNewContent = std::to_string(drRecord.iPriority) + " " + drRecord.sValue;
  }
  std::string sNewId = makeRecordId(sOldName, sOldType, sNewContent);
  spLog->info("PowerDNS: updated record {} → {} in zone {}", drRecord.sProviderRecordId, sNewId,
              sCanonical);
  return {true, sNewId, ""};
}

bool PowerDnsProvider::deleteRecord(const std::string& sZoneName,
                                    const std::string& sProviderRecordId) {
  auto spLog = common::Logger::get();
  std::string sCanonical = canonicalZone(sZoneName);
  std::string sPath = "/api/v1/servers/localhost/zones/" + sCanonical;

  std::string sTargetName, sTargetType, sTargetValue;
  if (!parseRecordId(sProviderRecordId, sTargetName, sTargetType, sTargetValue)) {
    return false;
  }

  // Fetch existing rrset, remove the target record
  auto vAll = listRecords(sZoneName);
  json jRecords = json::array();
  bool bFound = false;
  for (const auto& dr : vAll) {
    if (dr.sName != sTargetName || dr.sType != sTargetType) continue;
    std::string sCheckName, sCheckType, sCheckValue;
    parseRecordId(dr.sProviderRecordId, sCheckName, sCheckType, sCheckValue);
    if (sCheckValue == sTargetValue) {
      bFound = true;
      continue;  // skip — this is the one to delete
    }
    std::string sContent = dr.sValue;
    if ((dr.sType == "MX" || dr.sType == "SRV") && dr.iPriority > 0) {
      sContent = std::to_string(dr.iPriority) + " " + dr.sValue;
    }
    jRecords.push_back({{"content", sContent}, {"disabled", false}});
  }

  if (!bFound) return false;

  // If no records remain, delete the entire rrset; otherwise replace
  std::string sChangetype = jRecords.empty() ? "DELETE" : "REPLACE";
  json jRrset = {{"name", sTargetName}, {"type", sTargetType}, {"changetype", sChangetype}};
  if (!jRecords.empty()) {
    jRrset["ttl"] = vAll.front().uTtl;  // preserve TTL from existing
    jRrset["records"] = jRecords;
  }

  json jBody = {{"rrsets", {jRrset}}};
  auto res = _upClient->Patch(sPath, jBody.dump(), "application/json");
  if (!res) return false;
  if (res->status != 204 && res->status != 200) return false;

  spLog->info("PowerDNS: deleted record {} from zone {}", sProviderRecordId, sCanonical);
  return true;
}

}  // namespace dns::providers
```

### Step 5: Run tests to verify they pass

```bash
cmake --build build --parallel && build/tests/dns-tests --gtest_filter="PowerDns*"
```

Expected: All JSON parsing and record ID tests PASS.

### Step 6: Commit

```bash
git add include/providers/PowerDnsProvider.hpp src/providers/PowerDnsProvider.cpp \
  tests/unit/test_powerdns_provider.cpp
git commit -m "feat(providers): implement PowerDnsProvider with REST API v1 client"
```

---

## Task 6: DiffEngine — Header Update and Diff Algorithm

DiffEngine needs repositories and VariableEngine to compute the three-way diff. The diff
algorithm itself is a pure function that can be unit-tested independently.

**Diff logic:**
1. Fetch zone → view → providers from DAL
2. For each provider, call `listRecords()` to get live state
3. Fetch desired records from RecordRepository + expand via VariableEngine
4. Compare desired vs. live:
   - Record in desired but not live → `DiffAction::Add`
   - Record in both but value differs → `DiffAction::Update`
   - Record in live but not desired → `DiffAction::Drift`

Records are matched by (name, type, value) for exact matches, or (name, type) for update
detection.

**Files:**
- Modify: `include/core/DiffEngine.hpp` — add dependencies and static diff helper
- Modify: `src/core/DiffEngine.cpp` — full implementation
- Create: `tests/unit/test_diff_engine.cpp` — unit tests for pure diff algorithm

### Step 1: Update DiffEngine header

Replace `include/core/DiffEngine.hpp`:

```cpp
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "common/Types.hpp"

namespace dns::dal {
class ProviderRepository;
class RecordRepository;
class ViewRepository;
class ZoneRepository;
}  // namespace dns::dal

namespace dns::core {

class VariableEngine;

/// Computes three-way diff between staged records and live provider state.
/// Class abbreviation: de
class DiffEngine {
 public:
  DiffEngine(dns::dal::ZoneRepository& zrRepo,
             dns::dal::ViewRepository& vrRepo,
             dns::dal::RecordRepository& rrRepo,
             dns::dal::ProviderRepository& prRepo,
             VariableEngine& veEngine);
  ~DiffEngine();

  /// Compute diff between desired state (DB + variable expansion) and live
  /// provider state for the given zone. Queries all providers attached to the
  /// zone's view.
  common::PreviewResult preview(int64_t iZoneId);

  /// Pure diff algorithm: compare desired records against live records.
  /// Public for unit testing.
  /// Matching strategy: records are compared by (name, type). Within the same
  /// (name, type) group, values are compared for exact matches.
  static std::vector<common::RecordDiff> computeDiff(
      const std::vector<common::DnsRecord>& vDesired,
      const std::vector<common::DnsRecord>& vLive);

 private:
  dns::dal::ZoneRepository& _zrRepo;
  dns::dal::ViewRepository& _vrRepo;
  dns::dal::RecordRepository& _rrRepo;
  dns::dal::ProviderRepository& _prRepo;
  VariableEngine& _veEngine;
};

}  // namespace dns::core
```

### Step 2: Write failing unit tests for computeDiff()

Create `tests/unit/test_diff_engine.cpp`:

```cpp
#include "core/DiffEngine.hpp"

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "common/Types.hpp"

using dns::common::DiffAction;
using dns::common::DnsRecord;
using dns::common::RecordDiff;
using dns::core::DiffEngine;

namespace {
DnsRecord makeRecord(const std::string& sName, const std::string& sType,
                     const std::string& sValue, uint32_t uTtl = 300) {
  DnsRecord dr;
  dr.sName = sName;
  dr.sType = sType;
  dr.sValue = sValue;
  dr.uTtl = uTtl;
  return dr;
}
}  // namespace

TEST(DiffEngineComputeTest, BothEmpty) {
  auto vDiffs = DiffEngine::computeDiff({}, {});
  EXPECT_TRUE(vDiffs.empty());
}

TEST(DiffEngineComputeTest, AllNew) {
  std::vector<DnsRecord> vDesired = {makeRecord("www.example.com.", "A", "1.2.3.4")};
  std::vector<DnsRecord> vLive = {};
  auto vDiffs = DiffEngine::computeDiff(vDesired, vLive);
  ASSERT_EQ(vDiffs.size(), 1u);
  EXPECT_EQ(vDiffs[0].action, DiffAction::Add);
  EXPECT_EQ(vDiffs[0].sName, "www.example.com.");
  EXPECT_EQ(vDiffs[0].sType, "A");
  EXPECT_EQ(vDiffs[0].sSourceValue, "1.2.3.4");
  EXPECT_TRUE(vDiffs[0].sProviderValue.empty());
}

TEST(DiffEngineComputeTest, AllDrift) {
  std::vector<DnsRecord> vDesired = {};
  std::vector<DnsRecord> vLive = {makeRecord("rogue.example.com.", "A", "9.9.9.9")};
  auto vDiffs = DiffEngine::computeDiff(vDesired, vLive);
  ASSERT_EQ(vDiffs.size(), 1u);
  EXPECT_EQ(vDiffs[0].action, DiffAction::Drift);
  EXPECT_EQ(vDiffs[0].sProviderValue, "9.9.9.9");
  EXPECT_TRUE(vDiffs[0].sSourceValue.empty());
}

TEST(DiffEngineComputeTest, ExactMatch) {
  auto dr = makeRecord("www.example.com.", "A", "1.2.3.4");
  auto vDiffs = DiffEngine::computeDiff({dr}, {dr});
  EXPECT_TRUE(vDiffs.empty());
}

TEST(DiffEngineComputeTest, ValueChanged) {
  auto drDesired = makeRecord("www.example.com.", "A", "1.2.3.4");
  auto drLive = makeRecord("www.example.com.", "A", "5.6.7.8");
  auto vDiffs = DiffEngine::computeDiff({drDesired}, {drLive});
  ASSERT_EQ(vDiffs.size(), 1u);
  EXPECT_EQ(vDiffs[0].action, DiffAction::Update);
  EXPECT_EQ(vDiffs[0].sSourceValue, "1.2.3.4");
  EXPECT_EQ(vDiffs[0].sProviderValue, "5.6.7.8");
}

TEST(DiffEngineComputeTest, MixedActions) {
  std::vector<DnsRecord> vDesired = {
      makeRecord("www.example.com.", "A", "1.2.3.4"),       // matches live
      makeRecord("new.example.com.", "A", "10.0.0.1"),      // add
      makeRecord("mail.example.com.", "MX", "mail2.ex."),   // update (value differs)
  };
  std::vector<DnsRecord> vLive = {
      makeRecord("www.example.com.", "A", "1.2.3.4"),       // matches desired
      makeRecord("mail.example.com.", "MX", "mail1.ex."),   // update
      makeRecord("old.example.com.", "CNAME", "legacy."),   // drift
  };
  auto vDiffs = DiffEngine::computeDiff(vDesired, vLive);
  ASSERT_EQ(vDiffs.size(), 3u);

  // Sort by name for deterministic assertions
  std::sort(vDiffs.begin(), vDiffs.end(),
            [](const RecordDiff& a, const RecordDiff& b) { return a.sName < b.sName; });

  EXPECT_EQ(vDiffs[0].action, DiffAction::Update);   // mail
  EXPECT_EQ(vDiffs[1].action, DiffAction::Add);       // new
  EXPECT_EQ(vDiffs[2].action, DiffAction::Drift);     // old
}

TEST(DiffEngineComputeTest, MultipleRecordsSameNameType) {
  // Two A records for same name (e.g., round-robin)
  std::vector<DnsRecord> vDesired = {
      makeRecord("www.example.com.", "A", "1.2.3.4"),
      makeRecord("www.example.com.", "A", "5.6.7.8"),
  };
  std::vector<DnsRecord> vLive = {
      makeRecord("www.example.com.", "A", "1.2.3.4"),
      makeRecord("www.example.com.", "A", "5.6.7.8"),
  };
  auto vDiffs = DiffEngine::computeDiff(vDesired, vLive);
  EXPECT_TRUE(vDiffs.empty());
}

TEST(DiffEngineComputeTest, MultipleRecordsSameNameTypePartialDrift) {
  std::vector<DnsRecord> vDesired = {
      makeRecord("www.example.com.", "A", "1.2.3.4"),
  };
  std::vector<DnsRecord> vLive = {
      makeRecord("www.example.com.", "A", "1.2.3.4"),
      makeRecord("www.example.com.", "A", "9.9.9.9"),  // extra — drift
  };
  auto vDiffs = DiffEngine::computeDiff(vDesired, vLive);
  ASSERT_EQ(vDiffs.size(), 1u);
  EXPECT_EQ(vDiffs[0].action, DiffAction::Drift);
  EXPECT_EQ(vDiffs[0].sProviderValue, "9.9.9.9");
}
```

### Step 3: Run tests to verify they fail

```bash
cmake --build build --parallel && build/tests/dns-tests --gtest_filter="DiffEngine*"
```

Expected: FAIL — `computeDiff` doesn't exist yet; won't compile.

### Step 4: Implement DiffEngine

Replace `src/core/DiffEngine.cpp`:

```cpp
#include "core/DiffEngine.hpp"

#include <algorithm>
#include <chrono>
#include <set>
#include <string>
#include <vector>

#include "common/Errors.hpp"
#include "common/Logger.hpp"
#include "core/VariableEngine.hpp"
#include "dal/ProviderRepository.hpp"
#include "dal/RecordRepository.hpp"
#include "dal/ViewRepository.hpp"
#include "dal/ZoneRepository.hpp"
#include "providers/ProviderFactory.hpp"

namespace dns::core {

DiffEngine::DiffEngine(dns::dal::ZoneRepository& zrRepo,
                       dns::dal::ViewRepository& vrRepo,
                       dns::dal::RecordRepository& rrRepo,
                       dns::dal::ProviderRepository& prRepo,
                       VariableEngine& veEngine)
    : _zrRepo(zrRepo),
      _vrRepo(vrRepo),
      _rrRepo(rrRepo),
      _prRepo(prRepo),
      _veEngine(veEngine) {}

DiffEngine::~DiffEngine() = default;

std::vector<common::RecordDiff> DiffEngine::computeDiff(
    const std::vector<common::DnsRecord>& vDesired,
    const std::vector<common::DnsRecord>& vLive) {
  std::vector<common::RecordDiff> vDiffs;

  // Index live records by (name, type, value) for exact-match lookup
  // Use a set of "name/type/value" strings for O(1) lookup
  std::set<std::string> sLiveKeys;
  for (const auto& dr : vLive) {
    sLiveKeys.insert(dr.sName + "\t" + dr.sType + "\t" + dr.sValue);
  }

  std::set<std::string> sDesiredKeys;
  for (const auto& dr : vDesired) {
    sDesiredKeys.insert(dr.sName + "\t" + dr.sType + "\t" + dr.sValue);
  }

  // Build (name, type) → values maps for update detection
  // Map key: "name\ttype", value: set of values
  std::map<std::string, std::vector<std::string>> mDesiredByNameType;
  for (const auto& dr : vDesired) {
    std::string sKey = dr.sName + "\t" + dr.sType;
    mDesiredByNameType[sKey].push_back(dr.sValue);
  }

  std::map<std::string, std::vector<std::string>> mLiveByNameType;
  for (const auto& dr : vLive) {
    std::string sKey = dr.sName + "\t" + dr.sType;
    mLiveByNameType[sKey].push_back(dr.sValue);
  }

  // 1. Check desired records: Add or Update
  for (const auto& dr : vDesired) {
    std::string sExactKey = dr.sName + "\t" + dr.sType + "\t" + dr.sValue;
    if (sLiveKeys.count(sExactKey)) continue;  // exact match — no diff

    std::string sNameTypeKey = dr.sName + "\t" + dr.sType;
    auto itLive = mLiveByNameType.find(sNameTypeKey);
    if (itLive != mLiveByNameType.end() && !itLive->second.empty()) {
      // Same name+type exists on provider but value differs → Update
      // Find the first unmatched live value for this name+type
      std::string sProviderValue;
      for (const auto& sLiveVal : itLive->second) {
        std::string sLiveExact = dr.sName + "\t" + dr.sType + "\t" + sLiveVal;
        if (!sDesiredKeys.count(sLiveExact)) {
          sProviderValue = sLiveVal;
          break;
        }
      }
      if (!sProviderValue.empty()) {
        common::RecordDiff rd;
        rd.action = common::DiffAction::Update;
        rd.sName = dr.sName;
        rd.sType = dr.sType;
        rd.sSourceValue = dr.sValue;
        rd.sProviderValue = sProviderValue;
        vDiffs.push_back(std::move(rd));
      } else {
        // All live values for this name+type are matched — this is new
        common::RecordDiff rd;
        rd.action = common::DiffAction::Add;
        rd.sName = dr.sName;
        rd.sType = dr.sType;
        rd.sSourceValue = dr.sValue;
        vDiffs.push_back(std::move(rd));
      }
    } else {
      // name+type doesn't exist on provider at all → Add
      common::RecordDiff rd;
      rd.action = common::DiffAction::Add;
      rd.sName = dr.sName;
      rd.sType = dr.sType;
      rd.sSourceValue = dr.sValue;
      vDiffs.push_back(std::move(rd));
    }
  }

  // 2. Check live records for drift: records on provider but not in desired
  for (const auto& dr : vLive) {
    std::string sExactKey = dr.sName + "\t" + dr.sType + "\t" + dr.sValue;
    if (sDesiredKeys.count(sExactKey)) continue;  // matched — not drift

    // Check if this live record was already consumed as the "provider side" of an Update
    bool bConsumedByUpdate = false;
    for (const auto& diff : vDiffs) {
      if (diff.action == common::DiffAction::Update && diff.sName == dr.sName &&
          diff.sType == dr.sType && diff.sProviderValue == dr.sValue) {
        bConsumedByUpdate = true;
        break;
      }
    }
    if (bConsumedByUpdate) continue;

    common::RecordDiff rd;
    rd.action = common::DiffAction::Drift;
    rd.sName = dr.sName;
    rd.sType = dr.sType;
    rd.sProviderValue = dr.sValue;
    vDiffs.push_back(std::move(rd));
  }

  return vDiffs;
}

common::PreviewResult DiffEngine::preview(int64_t iZoneId) {
  auto spLog = common::Logger::get();

  // 1. Look up zone
  auto oZone = _zrRepo.findById(iZoneId);
  if (!oZone) {
    throw common::NotFoundError("ZONE_NOT_FOUND",
                                "Zone " + std::to_string(iZoneId) + " not found");
  }

  // 2. Look up view with providers
  auto oView = _vrRepo.findWithProviders(oZone->iViewId);
  if (!oView) {
    throw common::NotFoundError("VIEW_NOT_FOUND",
                                "View " + std::to_string(oZone->iViewId) + " not found");
  }
  if (oView->vProviderIds.empty()) {
    throw common::ValidationError("NO_PROVIDERS",
                                  "View '" + oView->sName + "' has no providers attached");
  }

  // 3. Fetch desired records from DB and expand templates
  auto vRecordRows = _rrRepo.listByZoneId(iZoneId);
  std::vector<common::DnsRecord> vDesired;
  vDesired.reserve(vRecordRows.size());
  for (const auto& row : vRecordRows) {
    common::DnsRecord dr;
    dr.sName = row.sName;
    dr.sType = row.sType;
    dr.uTtl = static_cast<uint32_t>(row.iTtl);
    dr.sValue = _veEngine.expand(row.sValueTemplate, iZoneId);
    dr.iPriority = row.iPriority;
    vDesired.push_back(std::move(dr));
  }

  // 4. Fetch live records from all providers for this zone
  std::vector<common::DnsRecord> vLive;
  for (int64_t iProviderId : oView->vProviderIds) {
    auto oProvider = _prRepo.findById(iProviderId);
    if (!oProvider) {
      spLog->warn("Provider {} not found — skipping", iProviderId);
      continue;
    }

    auto upProvider = dns::providers::ProviderFactory::create(
        oProvider->sType, oProvider->sApiEndpoint, oProvider->sDecryptedToken);

    try {
      auto vProviderRecords = upProvider->listRecords(oZone->sName);
      vLive.insert(vLive.end(), vProviderRecords.begin(), vProviderRecords.end());
    } catch (const common::ProviderError& ex) {
      spLog->error("Failed to list records from provider '{}': {}", oProvider->sName, ex.what());
      throw;
    }
  }

  // 5. Compute diff
  auto vDiffs = computeDiff(vDesired, vLive);

  // 6. Build result
  common::PreviewResult pr;
  pr.iZoneId = iZoneId;
  pr.sZoneName = oZone->sName;
  pr.vDiffs = std::move(vDiffs);
  pr.bHasDrift = std::any_of(pr.vDiffs.begin(), pr.vDiffs.end(),
                              [](const common::RecordDiff& rd) {
                                return rd.action == common::DiffAction::Drift;
                              });
  pr.tpGeneratedAt = std::chrono::system_clock::now();

  spLog->info("DiffEngine: zone '{}' — {} diffs, drift={}", oZone->sName, pr.vDiffs.size(),
              pr.bHasDrift);
  return pr;
}

}  // namespace dns::core
```

### Step 5: Run tests to verify they pass

```bash
cmake --build build --parallel && build/tests/dns-tests --gtest_filter="DiffEngine*"
```

Expected: All unit tests PASS.

### Step 6: Commit

```bash
git add include/core/DiffEngine.hpp src/core/DiffEngine.cpp tests/unit/test_diff_engine.cpp
git commit -m "feat(core): implement DiffEngine with three-way diff algorithm"
```

---

## Task 7: HealthRoutes

Simple unauthenticated endpoint returning `{"status":"ok"}`. No auth middleware needed.

**Files:**
- Modify: `include/api/routes/HealthRoutes.hpp` — add `crow::SimpleApp&` param
- Modify: `src/api/routes/HealthRoutes.cpp` — implement route
- Modify: `include/api/ApiServer.hpp` — add HealthRoutes member
- Modify: `src/api/ApiServer.cpp` — register HealthRoutes

### Step 1: Update HealthRoutes header

Replace `include/api/routes/HealthRoutes.hpp`:

```cpp
#pragma once

#include <crow.h>

namespace dns::api::routes {

/// Handler for GET /api/v1/health (no auth required)
class HealthRoutes {
 public:
  HealthRoutes();
  ~HealthRoutes();

  /// Register health route on the Crow app.
  void registerRoutes(crow::SimpleApp& app);
};

}  // namespace dns::api::routes
```

### Step 2: Implement HealthRoutes

Replace `src/api/routes/HealthRoutes.cpp`:

```cpp
#include "api/routes/HealthRoutes.hpp"

#include <crow.h>
#include <nlohmann/json.hpp>

namespace dns::api::routes {

HealthRoutes::HealthRoutes() = default;
HealthRoutes::~HealthRoutes() = default;

void HealthRoutes::registerRoutes(crow::SimpleApp& app) {
  CROW_ROUTE(app, "/api/v1/health")
      .methods(crow::HTTPMethod::GET)([](const crow::request& /*req*/) {
        nlohmann::json jResp = {{"status", "ok"}};
        auto resp = crow::response(200, jResp.dump());
        resp.set_header("Content-Type", "application/json");
        return resp;
      });
}

}  // namespace dns::api::routes
```

### Step 3: Update ApiServer to include HealthRoutes

Update `include/api/ApiServer.hpp` — add forward declaration and member:

```cpp
#pragma once

#include <crow.h>

namespace dns::api {
class AuthMiddleware;
}

namespace dns::api::routes {
class AuthRoutes;
class HealthRoutes;
class ProviderRoutes;
class ViewRoutes;
class ZoneRoutes;
class RecordRoutes;
class VariableRoutes;
}  // namespace dns::api::routes

namespace dns::api {

/// Owns the Crow application instance; registers all routes at startup.
/// Class abbreviation: api
class ApiServer {
 public:
  ApiServer(crow::SimpleApp& app,
            routes::AuthRoutes& arRoutes,
            routes::HealthRoutes& hrRoutes,
            routes::ProviderRoutes& prRoutes,
            routes::ViewRoutes& vrRoutes,
            routes::ZoneRoutes& zrRoutes,
            routes::RecordRoutes& rrRoutes,
            routes::VariableRoutes& varRoutes);
  ~ApiServer();

  /// Register all route handlers on the Crow app.
  void registerRoutes();

  /// Start the HTTP server. Blocks on the Crow event loop.
  void start(int iPort, int iThreads);

  /// Stop the HTTP server.
  void stop();

 private:
  crow::SimpleApp& _app;
  routes::AuthRoutes& _arRoutes;
  routes::HealthRoutes& _hrRoutes;
  routes::ProviderRoutes& _prRoutes;
  routes::ViewRoutes& _vrRoutes;
  routes::ZoneRoutes& _zrRoutes;
  routes::RecordRoutes& _rrRoutes;
  routes::VariableRoutes& _varRoutes;
};

}  // namespace dns::api
```

### Step 4: Update ApiServer implementation

Replace `src/api/ApiServer.cpp`:

```cpp
#include "api/ApiServer.hpp"

#include "api/routes/AuthRoutes.hpp"
#include "api/routes/HealthRoutes.hpp"
#include "api/routes/ProviderRoutes.hpp"
#include "api/routes/RecordRoutes.hpp"
#include "api/routes/VariableRoutes.hpp"
#include "api/routes/ViewRoutes.hpp"
#include "api/routes/ZoneRoutes.hpp"

namespace dns::api {

ApiServer::ApiServer(crow::SimpleApp& app,
                     routes::AuthRoutes& arRoutes,
                     routes::HealthRoutes& hrRoutes,
                     routes::ProviderRoutes& prRoutes,
                     routes::ViewRoutes& vrRoutes,
                     routes::ZoneRoutes& zrRoutes,
                     routes::RecordRoutes& rrRoutes,
                     routes::VariableRoutes& varRoutes)
    : _app(app),
      _arRoutes(arRoutes),
      _hrRoutes(hrRoutes),
      _prRoutes(prRoutes),
      _vrRoutes(vrRoutes),
      _zrRoutes(zrRoutes),
      _rrRoutes(rrRoutes),
      _varRoutes(varRoutes) {}

ApiServer::~ApiServer() = default;

void ApiServer::registerRoutes() {
  _hrRoutes.registerRoutes(_app);
  _arRoutes.registerRoutes(_app);
  _prRoutes.registerRoutes(_app);
  _vrRoutes.registerRoutes(_app);
  _zrRoutes.registerRoutes(_app);
  _rrRoutes.registerRoutes(_app);
  _varRoutes.registerRoutes(_app);
}

void ApiServer::start(int iPort, int iThreads) {
  _app.port(iPort).multithreaded().concurrency(iThreads).run();
}

void ApiServer::stop() {
  _app.stop();
}

}  // namespace dns::api
```

### Step 5: Build to verify compilation

```bash
cmake --build build --parallel
```

Expected: Build fails — `main.cpp` still uses the old ApiServer constructor signature.
This is expected and will be fixed in Task 8.

### Step 6: Commit (partial — will fix main.cpp in Task 8)

Do NOT commit yet. Proceed to Task 8 to fix main.cpp first.

---

## Task 8: Wire Everything in main.cpp

Update the startup sequence to:
- Construct `VariableEngine` with `VariableRepository`
- Construct `DiffEngine` with all repository dependencies
- Construct `HealthRoutes` and pass to `ApiServer`
- Remove Step 9 "not yet implemented" warning (ProviderFactory is a static class — no startup
  construction needed, but the step is logically complete now)

**Files:**
- Modify: `src/main.cpp`

### Step 1: Update main.cpp

Apply these changes to `src/main.cpp`:

**1. Add new includes** (after existing includes):

```cpp
#include "api/routes/HealthRoutes.hpp"
#include "core/DiffEngine.hpp"
#include "core/VariableEngine.hpp"
```

**2. Replace Step 9 warning** (around line 158-159):

Replace:
```cpp
// ── Step 9: ProviderFactory — deferred to Phase 6 ────────────────────
spLog->warn("Step 9: ProviderFactory — not yet implemented");
```

With:
```cpp
// ── Step 9: Core engines ─────────────────────────────────────────────
auto veEngine = std::make_unique<dns::core::VariableEngine>(*varRepo);
auto deEngine = std::make_unique<dns::core::DiffEngine>(
    *zrRepo, *vrRepo, *rrRepo, *prRepo, *veEngine);
spLog->info("Step 9: Core engines initialized (VariableEngine, DiffEngine)");
```

**3. Add HealthRoutes construction** (in Step 10, before ApiServer construction):

After the `variableRoutes` line, add:
```cpp
auto healthRoutes = std::make_unique<dns::api::routes::HealthRoutes>();
```

**4. Update ApiServer construction** to include `healthRoutes`:

Replace:
```cpp
auto apiServer = std::make_unique<dns::api::ApiServer>(
    crowApp, *authRoutes, *providerRoutes, *viewRoutes,
    *zoneRoutes, *recordRoutes, *variableRoutes);
```

With:
```cpp
auto apiServer = std::make_unique<dns::api::ApiServer>(
    crowApp, *authRoutes, *healthRoutes, *providerRoutes, *viewRoutes,
    *zoneRoutes, *recordRoutes, *variableRoutes);
```

**5. Update the Phase comment** at the top of main.cpp:

Replace:
```cpp
// Phase 5 implements steps 1-5, 7a, 8, 10, 11. Steps 6, 7, 9, 12 remain deferred.
```

With:
```cpp
// Phase 6 implements steps 1-5, 7a, 8, 9, 10, 11. Steps 6, 7, 12 remain deferred.
```

### Step 2: Build to verify full compilation

```bash
cmake --build build --parallel
```

Expected: Clean build.

### Step 3: Run all tests

```bash
build/tests/dns-tests
```

Expected: All existing tests still pass. New unit tests pass. Integration tests pass if
`DNS_DB_URL` is set, skip otherwise.

### Step 4: Commit everything from Tasks 7 + 8

```bash
git add include/api/routes/HealthRoutes.hpp src/api/routes/HealthRoutes.cpp \
  include/api/ApiServer.hpp src/api/ApiServer.cpp src/main.cpp
git commit -m "feat(api): implement HealthRoutes and wire Phase 6 engines into startup"
```

---

## Task 9: Update CLAUDE.md and Documentation

Update project documentation to reflect Phase 6 completion.

**Files:**
- Modify: `CLAUDE.md`

### Step 1: Update CLAUDE.md project status

In `CLAUDE.md`, update the project status section:

**Replace:**
```
- **Phase 5 complete:** DAL: Core Repositories + CRUD API Routes
- **Next task:** Phase 6 — PowerDNS Provider + Core Engines
- **Tests:** 129 total (58 pass, 71 skip — DB integration tests need `DNS_DB_URL`)
```

**With** (adjust test count after running):
```
- **Phase 6 complete:** PowerDNS Provider + Core Engines
- **Next task:** Phase 7 — Deployment Pipeline + GitOps
- **Tests:** XXX total (YY pass, ZZ skip — DB integration tests need `DNS_DB_URL`)
```

Update the startup sequence state:
```
Startup sequence: steps 1–5, 7a, 8, 9, 10, 11 wired in `src/main.cpp`. Remaining deferred:
- Step 6: GitOpsMirror → Phase 7
- Step 7: ThreadPool → Phase 7
- Step 12: Background task queue → Phase 7
```

### Step 2: Add Phase 6 summary to CLAUDE.md

Add a new `### Phase 6` section after the Phase 5 section, following the same format:

```markdown
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
- `CMakeLists.txt` — added cpp-httplib via FetchContent for HTTP client
- `src/main.cpp` — wired Step 9 (core engines), HealthRoutes into ApiServer

**Tests:** XX new tests (VariableEngine unit + integration, ProviderFactory, PowerDNS JSON parsing,
DiffEngine diff algorithm)
```

### Step 3: Commit

```bash
git add CLAUDE.md
git commit -m "docs: update CLAUDE.md for Phase 6 completion"
```

---

## Summary — Build Order and Dependencies

```
Task 1: cpp-httplib dependency        ← no deps, CMake only
Task 2: VariableEngine listDeps       ← no deps, pure string parsing
Task 3: VariableEngine expand/validate← depends on Task 2 + VariableRepository (existing)
Task 4: ProviderFactory               ← depends on Task 1 (PowerDnsProvider needs httplib)
Task 5: PowerDnsProvider              ← depends on Tasks 1, 4
Task 6: DiffEngine                    ← depends on Tasks 3, 5 + repositories (existing)
Task 7: HealthRoutes + ApiServer      ← independent of Tasks 2-6
Task 8: main.cpp wiring               ← depends on all above
Task 9: Documentation                 ← depends on all above
```

Tasks 1 and 2 can be done in parallel. Tasks 4 and 7 can be done in parallel after Task 1.
The critical path is: Task 1 → Task 5 → Task 6 → Task 8 → Task 9.

## Test Expectations

| Test File | Type | Count | Requires |
|-----------|------|-------|----------|
| `tests/unit/test_variable_engine.cpp` | Unit | ~8 | Nothing |
| `tests/integration/test_variable_engine_expand.cpp` | Integration | ~9 | `DNS_DB_URL` |
| `tests/unit/test_provider_factory.cpp` | Unit | ~4 | Nothing |
| `tests/unit/test_powerdns_provider.cpp` | Unit | ~8 | Nothing |
| `tests/unit/test_diff_engine.cpp` | Unit | ~8 | Nothing |
| **Total new** | | **~37** | |
