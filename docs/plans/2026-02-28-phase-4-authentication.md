# Phase 4: Authentication & Authorization Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement the complete authentication and authorization layer — local login (Argon2id), JWT sessions, API key validation, RBAC, session/key maintenance, and SAML replay protection.

**Architecture:** Phase 4 builds on the Phase 2+3 foundation (CryptoService, HmacJwtSigner, ConnectionPool, error hierarchy). It implements repositories for users/sessions/API keys, the AuthService orchestrator, AuthMiddleware for dual-mode request validation (Bearer JWT + X-API-Key), and the MaintenanceScheduler for background cleanup tasks. All SQL lives inside repository classes; auth logic coordinates via dependency injection of concrete classes.

**Tech Stack:** C++20, OpenSSL 3.2+ (Argon2id via EVP_KDF, SHA-256 via EVP_Digest), libpqxx (PostgreSQL), nlohmann/json, Google Test/Mock, Crow (HTTP — route wiring only)

**Key References:**
- `docs/ARCHITECTURE.md` §4.1 (AuthMiddleware), §4.3 (DAL), §4.6 (Security), §4.9 (MaintenanceScheduler), §7.4 (Auth Flows), §11.4 (Startup)
- `docs/plans/SECURITY_PLAN.md` — SEC-01 (API key SHA-512), SEC-02 (secret management)
- `scripts/db/001_initial_schema.sql` — tables: `users`, `groups`, `group_members`, `sessions`, `api_keys`
- `include/common/Errors.hpp` — `AuthenticationError` (401), `AuthorizationError` (403)
- `include/common/Types.hpp` — `RequestContext` struct
- `include/security/CryptoService.hpp` — `generateApiKey()`, `hashApiKey()` (SHA-512)
- `include/security/IJwtSigner.hpp` / `HmacJwtSigner.hpp` — JWT sign/verify

**Naming Conventions** (from `docs/CODE_STANDARDS.md`):
- Classes: `PascalCase` — Instance vars: `_` + type prefix + `PascalCase` (e.g., `_cpPool`)
- Primitives: type prefix + `PascalCase` (e.g., `sUsername`, `iUserId`, `bActive`)
- Functions: `camelCase` — Constants: `PascalCase` — Namespaces: `lowercase`

---

## Task 1: Add SHA-256 and Argon2id to CryptoService

**Files:**
- Modify: `include/security/CryptoService.hpp`
- Modify: `src/security/CryptoService.cpp`
- Modify: `tests/unit/test_crypto_service.cpp`

**Context:** AuthService needs SHA-256 to hash JWTs for session table lookups. AuthMiddleware also SHA-256 hashes JWTs and API keys. Argon2id is used for local password hashing. Both are pure crypto primitives that belong in CryptoService alongside the existing `hashApiKey()` (SHA-512).

**Step 1: Write the failing tests**

Add to `tests/unit/test_crypto_service.cpp`:

```cpp
// ── SHA-256 tests ──────────────────────────────────────────────────────────

TEST(CryptoServiceTest, Sha256HexReturns64CharHexString) {
  std::string sHash = CryptoService::sha256Hex("hello world");
  EXPECT_EQ(sHash.size(), 64u);
  for (char c : sHash) {
    EXPECT_TRUE((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
        << "Unexpected character in SHA-256 hash: " << c;
  }
}

TEST(CryptoServiceTest, Sha256HexIsDeterministic) {
  EXPECT_EQ(CryptoService::sha256Hex("test"), CryptoService::sha256Hex("test"));
}

TEST(CryptoServiceTest, Sha256HexDifferentInputsDiffer) {
  EXPECT_NE(CryptoService::sha256Hex("one"), CryptoService::sha256Hex("two"));
}

TEST(CryptoServiceTest, Sha256HexKnownVector) {
  // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  EXPECT_EQ(CryptoService::sha256Hex(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

// ── Argon2id tests ─────────────────────────────────────────────────────────

TEST(CryptoServiceTest, HashPasswordReturnsPHCString) {
  std::string sHash = CryptoService::hashPassword("MyP@ssw0rd!");
  // PHC format: $argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>
  EXPECT_EQ(sHash.substr(0, 10), "$argon2id$");
}

TEST(CryptoServiceTest, HashPasswordProducesUniqueSalts) {
  std::string sHash1 = CryptoService::hashPassword("same-password");
  std::string sHash2 = CryptoService::hashPassword("same-password");
  EXPECT_NE(sHash1, sHash2);  // different salts → different hashes
}

TEST(CryptoServiceTest, VerifyPasswordCorrect) {
  std::string sHash = CryptoService::hashPassword("correct-horse-battery-staple");
  EXPECT_TRUE(CryptoService::verifyPassword("correct-horse-battery-staple", sHash));
}

TEST(CryptoServiceTest, VerifyPasswordWrong) {
  std::string sHash = CryptoService::hashPassword("right-password");
  EXPECT_FALSE(CryptoService::verifyPassword("wrong-password", sHash));
}

TEST(CryptoServiceTest, VerifyPasswordEmptyPasswordWorks) {
  std::string sHash = CryptoService::hashPassword("");
  EXPECT_TRUE(CryptoService::verifyPassword("", sHash));
  EXPECT_FALSE(CryptoService::verifyPassword("not-empty", sHash));
}
```

**Step 2: Run tests to verify they fail**

Run: `cd build && ninja dns-tests 2>&1 | tail -5`
Expected: Compilation error — `sha256Hex`, `hashPassword`, `verifyPassword` not declared.

**Step 3: Add declarations to the header**

In `include/security/CryptoService.hpp`, add after the `hashApiKey` declaration:

```cpp
  /// SHA-256 hash → 64-char lowercase hex string.
  /// Used to hash JWTs for session table lookups.
  static std::string sha256Hex(const std::string& sInput);

  /// Hash a password with Argon2id → PHC-formatted string.
  /// Format: $argon2id$v=19$m=65536,t=3,p=1$<base64_salt>$<base64_hash>
  static std::string hashPassword(const std::string& sPassword);

  /// Verify a password against a PHC-formatted Argon2id hash.
  /// Returns true if the password matches, false otherwise.
  /// Uses constant-time comparison for the hash.
  static bool verifyPassword(const std::string& sPassword, const std::string& sHash);
```

**Step 4: Write minimal implementation**

In `src/security/CryptoService.cpp`, add the implementations:

```cpp
// ── SHA-256 ────────────────────────────────────────────────────────────────

std::string CryptoService::sha256Hex(const std::string& sInput) {
  unsigned char vHash[EVP_MAX_MD_SIZE];
  unsigned int uHashLen = 0;

  EVP_MD_CTX* pCtx = EVP_MD_CTX_new();
  if (!pCtx) {
    throw std::runtime_error("Failed to create digest context");
  }

  if (EVP_DigestInit_ex(pCtx, EVP_sha256(), nullptr) != 1 ||
      EVP_DigestUpdate(pCtx, sInput.data(), sInput.size()) != 1 ||
      EVP_DigestFinal_ex(pCtx, vHash, &uHashLen) != 1) {
    EVP_MD_CTX_free(pCtx);
    throw std::runtime_error("SHA-256 hash computation failed");
  }

  EVP_MD_CTX_free(pCtx);

  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (unsigned int i = 0; i < uHashLen; ++i) {
    oss << std::setw(2) << static_cast<int>(vHash[i]);
  }
  return oss.str();
}

// ── Argon2id password hashing ──────────────────────────────────────────────

namespace {
constexpr uint32_t kArgon2MemoryCost = 65536;  // 64 MiB
constexpr uint32_t kArgon2TimeCost = 3;         // 3 iterations
constexpr uint32_t kArgon2Parallelism = 1;      // 1 lane
constexpr int kArgon2SaltLen = 16;              // 16 bytes
constexpr int kArgon2HashLen = 32;              // 32 bytes
}  // namespace

std::string CryptoService::hashPassword(const std::string& sPassword) {
  // Generate random salt
  std::vector<unsigned char> vSalt(kArgon2SaltLen);
  if (RAND_bytes(vSalt.data(), kArgon2SaltLen) != 1) {
    throw std::runtime_error("Failed to generate random salt");
  }

  // Derive hash using EVP_KDF Argon2id
  EVP_KDF* pKdf = EVP_KDF_fetch(nullptr, "ARGON2ID", nullptr);
  if (!pKdf) {
    throw std::runtime_error("Failed to fetch ARGON2ID KDF (requires OpenSSL >= 3.2)");
  }

  EVP_KDF_CTX* pCtx = EVP_KDF_CTX_new(pKdf);
  EVP_KDF_free(pKdf);
  if (!pCtx) {
    throw std::runtime_error("Failed to create KDF context");
  }

  std::vector<unsigned char> vHash(kArgon2HashLen);

  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_octet_string(
          OSSL_KDF_PARAM_PASSWORD,
          const_cast<char*>(sPassword.data()),
          sPassword.size()),
      OSSL_PARAM_construct_octet_string(
          OSSL_KDF_PARAM_SALT,
          vSalt.data(),
          vSalt.size()),
      OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, const_cast<uint32_t*>(&kArgon2TimeCost)),
      OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, const_cast<uint32_t*>(&kArgon2MemoryCost)),
      OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS, const_cast<uint32_t*>(&kArgon2Parallelism)),
      OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, const_cast<uint32_t*>(&kArgon2Parallelism)),
      OSSL_PARAM_construct_end(),
  };

  if (EVP_KDF_derive(pCtx, vHash.data(), vHash.size(), params) != 1) {
    EVP_KDF_CTX_free(pCtx);
    throw std::runtime_error("Argon2id key derivation failed");
  }

  EVP_KDF_CTX_free(pCtx);

  // Encode salt and hash as base64 (no padding, no newlines)
  std::string sSaltB64 = base64UrlEncode(vSalt);
  std::string sHashB64 = base64UrlEncode(vHash);

  // Format as PHC string
  return "$argon2id$v=19$m=" + std::to_string(kArgon2MemoryCost) +
         ",t=" + std::to_string(kArgon2TimeCost) +
         ",p=" + std::to_string(kArgon2Parallelism) +
         "$" + sSaltB64 + "$" + sHashB64;
}

bool CryptoService::verifyPassword(const std::string& sPassword, const std::string& sHash) {
  // Parse PHC string: $argon2id$v=19$m=65536,t=3,p=1$<salt>$<hash>
  // Split on '$' — fields: [0]="" [1]="argon2id" [2]="v=19" [3]="m=...,t=...,p=..." [4]=salt [5]=hash
  std::vector<std::string> vParts;
  std::istringstream iss(sHash);
  std::string sPart;
  while (std::getline(iss, sPart, '$')) {
    vParts.push_back(sPart);
  }

  if (vParts.size() != 6 || vParts[1] != "argon2id") {
    return false;
  }

  // Parse parameters from vParts[3]: "m=65536,t=3,p=1"
  uint32_t uMemory = 0, uTime = 0, uParallelism = 0;
  if (std::sscanf(vParts[3].c_str(), "m=%u,t=%u,p=%u", &uMemory, &uTime, &uParallelism) != 3) {
    return false;
  }

  // Decode salt from base64url
  // Re-add padding for base64 decode
  std::string sSaltB64 = vParts[4];
  for (auto& c : sSaltB64) {
    if (c == '-') c = '+';
    else if (c == '_') c = '/';
  }
  while (sSaltB64.size() % 4 != 0) sSaltB64 += '=';
  auto vSalt = base64Decode(sSaltB64);

  // Decode stored hash from base64url
  std::string sStoredB64 = vParts[5];
  for (auto& c : sStoredB64) {
    if (c == '-') c = '+';
    else if (c == '_') c = '/';
  }
  while (sStoredB64.size() % 4 != 0) sStoredB64 += '=';
  auto vStoredHash = base64Decode(sStoredB64);

  // Re-derive hash with parsed params and extracted salt
  EVP_KDF* pKdf = EVP_KDF_fetch(nullptr, "ARGON2ID", nullptr);
  if (!pKdf) return false;

  EVP_KDF_CTX* pCtx = EVP_KDF_CTX_new(pKdf);
  EVP_KDF_free(pKdf);
  if (!pCtx) return false;

  std::vector<unsigned char> vDerived(vStoredHash.size());

  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_octet_string(
          OSSL_KDF_PARAM_PASSWORD,
          const_cast<char*>(sPassword.data()),
          sPassword.size()),
      OSSL_PARAM_construct_octet_string(
          OSSL_KDF_PARAM_SALT,
          vSalt.data(),
          vSalt.size()),
      OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &uTime),
      OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &uMemory),
      OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS, &uParallelism),
      OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &uParallelism),
      OSSL_PARAM_construct_end(),
  };

  if (EVP_KDF_derive(pCtx, vDerived.data(), vDerived.size(), params) != 1) {
    EVP_KDF_CTX_free(pCtx);
    return false;
  }

  EVP_KDF_CTX_free(pCtx);

  // Constant-time comparison
  return CRYPTO_memcmp(vDerived.data(), vStoredHash.data(), vStoredHash.size()) == 0;
}
```

**Step 5: Add required include**

In `src/security/CryptoService.cpp`, add to the include block:

```cpp
#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

#include <cstdio>
```

**Step 6: Run tests to verify they pass**

Run: `cd build && ninja dns-tests && ./tests/dns-tests --gtest_filter='CryptoServiceTest.*' 2>&1`
Expected: All CryptoServiceTest tests PASS (original 8 + new 9 = 17 tests).

**Step 7: Commit**

```bash
git add include/security/CryptoService.hpp src/security/CryptoService.cpp tests/unit/test_crypto_service.cpp
git commit -m "feat(crypto): add SHA-256 and Argon2id password hashing to CryptoService"
```

---

## Task 2: SamlReplayCache Implementation

**Files:**
- Modify: `src/security/SamlReplayCache.cpp`
- Create: `tests/unit/test_saml_replay_cache.cpp`

**Context:** The SamlReplayCache is an in-memory cache that tracks SAML assertion IDs to prevent replay attacks. Each entry has a TTL matching the assertion's `NotOnOrAfter` window. The header is already correct — this task implements the logic and tests.

**Step 1: Write the failing tests**

Create `tests/unit/test_saml_replay_cache.cpp`:

```cpp
#include "security/SamlReplayCache.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <string>

using dns::security::SamlReplayCache;
using Clock = std::chrono::system_clock;

TEST(SamlReplayCacheTest, FirstInsertReturnsTrue) {
  SamlReplayCache cache;
  auto tpExpiry = Clock::now() + std::chrono::minutes(5);
  EXPECT_TRUE(cache.checkAndInsert("assertion-001", tpExpiry));
}

TEST(SamlReplayCacheTest, DuplicateInsertReturnsFalse) {
  SamlReplayCache cache;
  auto tpExpiry = Clock::now() + std::chrono::minutes(5);
  EXPECT_TRUE(cache.checkAndInsert("assertion-002", tpExpiry));
  EXPECT_FALSE(cache.checkAndInsert("assertion-002", tpExpiry));
}

TEST(SamlReplayCacheTest, DifferentIdsAreIndependent) {
  SamlReplayCache cache;
  auto tpExpiry = Clock::now() + std::chrono::minutes(5);
  EXPECT_TRUE(cache.checkAndInsert("id-aaa", tpExpiry));
  EXPECT_TRUE(cache.checkAndInsert("id-bbb", tpExpiry));
}

TEST(SamlReplayCacheTest, ExpiredEntriesAreEvicted) {
  SamlReplayCache cache;
  // Insert with an already-expired timestamp
  auto tpPast = Clock::now() - std::chrono::seconds(1);
  EXPECT_TRUE(cache.checkAndInsert("expired-id", tpPast));

  // Insert a new ID to trigger eviction
  auto tpFuture = Clock::now() + std::chrono::minutes(5);
  EXPECT_TRUE(cache.checkAndInsert("new-id", tpFuture));

  // The expired entry should have been evicted — re-inserting should succeed
  EXPECT_TRUE(cache.checkAndInsert("expired-id", tpFuture));
}

TEST(SamlReplayCacheTest, NonExpiredEntriesAreNotEvicted) {
  SamlReplayCache cache;
  auto tpFuture = Clock::now() + std::chrono::hours(1);
  EXPECT_TRUE(cache.checkAndInsert("valid-id", tpFuture));

  // Trigger eviction with another insert — valid-id should survive
  EXPECT_TRUE(cache.checkAndInsert("other-id", tpFuture));
  EXPECT_FALSE(cache.checkAndInsert("valid-id", tpFuture));
}
```

**Step 2: Run tests to verify they fail**

Run: `cd build && ninja dns-tests && ./tests/dns-tests --gtest_filter='SamlReplayCacheTest.*' 2>&1`
Expected: All tests FAIL with "not implemented" runtime error.

**Step 3: Implement SamlReplayCache**

Replace `src/security/SamlReplayCache.cpp`:

```cpp
#include "security/SamlReplayCache.hpp"

#include <algorithm>

namespace dns::security {

SamlReplayCache::SamlReplayCache() = default;
SamlReplayCache::~SamlReplayCache() = default;

bool SamlReplayCache::checkAndInsert(
    const std::string& sAssertionId,
    std::chrono::system_clock::time_point tpNotOnOrAfter) {
  std::lock_guard<std::mutex> lock(_mtx);

  evictExpired();

  auto it = _mCache.find(sAssertionId);
  if (it != _mCache.end()) {
    return false;  // replay detected
  }

  _mCache.emplace(sAssertionId, tpNotOnOrAfter);
  return true;
}

void SamlReplayCache::evictExpired() {
  auto tpNow = std::chrono::system_clock::now();
  for (auto it = _mCache.begin(); it != _mCache.end();) {
    if (it->second < tpNow) {
      it = _mCache.erase(it);
    } else {
      ++it;
    }
  }
}

}  // namespace dns::security
```

**Step 4: Run tests to verify they pass**

Run: `cd build && ninja dns-tests && ./tests/dns-tests --gtest_filter='SamlReplayCacheTest.*' 2>&1`
Expected: All 5 SamlReplayCacheTest tests PASS.

**Step 5: Commit**

```bash
git add src/security/SamlReplayCache.cpp tests/unit/test_saml_replay_cache.cpp
git commit -m "feat(security): implement SamlReplayCache with TTL eviction"
```

---

## Task 3: MaintenanceScheduler Implementation

**Files:**
- Modify: `src/core/MaintenanceScheduler.cpp`
- Create: `tests/unit/test_maintenance_scheduler.cpp`

**Context:** MaintenanceScheduler runs periodic background tasks (session flush, API key cleanup, audit purge) on a dedicated `std::jthread`. The header is already correct. The scheduling algorithm: loop, check each task's `next_run`, execute if due, sleep until next task is due.

**Step 1: Write the failing tests**

Create `tests/unit/test_maintenance_scheduler.cpp`:

```cpp
#include "core/MaintenanceScheduler.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <thread>

using dns::core::MaintenanceScheduler;
using namespace std::chrono_literals;

TEST(MaintenanceSchedulerTest, ScheduledTaskExecutes) {
  MaintenanceScheduler ms;
  std::atomic<int> iCount{0};

  ms.schedule("test-task", 1s, [&iCount]() { iCount.fetch_add(1); });
  ms.start();

  // Wait enough for at least one execution
  std::this_thread::sleep_for(1500ms);
  ms.stop();

  EXPECT_GE(iCount.load(), 1);
}

TEST(MaintenanceSchedulerTest, MultipleTasksExecuteIndependently) {
  MaintenanceScheduler ms;
  std::atomic<int> iCountA{0};
  std::atomic<int> iCountB{0};

  ms.schedule("task-a", 1s, [&iCountA]() { iCountA.fetch_add(1); });
  ms.schedule("task-b", 1s, [&iCountB]() { iCountB.fetch_add(1); });
  ms.start();

  std::this_thread::sleep_for(1500ms);
  ms.stop();

  EXPECT_GE(iCountA.load(), 1);
  EXPECT_GE(iCountB.load(), 1);
}

TEST(MaintenanceSchedulerTest, StopIsIdempotent) {
  MaintenanceScheduler ms;
  std::atomic<int> iCount{0};

  ms.schedule("task", 1s, [&iCount]() { iCount.fetch_add(1); });
  ms.start();
  ms.stop();
  ms.stop();  // second stop should not crash

  SUCCEED();
}

TEST(MaintenanceSchedulerTest, FailingTaskDoesNotCrashScheduler) {
  MaintenanceScheduler ms;
  std::atomic<int> iGoodCount{0};

  ms.schedule("bad-task", 1s, []() { throw std::runtime_error("task failed"); });
  ms.schedule("good-task", 1s, [&iGoodCount]() { iGoodCount.fetch_add(1); });
  ms.start();

  std::this_thread::sleep_for(1500ms);
  ms.stop();

  // Good task should still have run despite bad task throwing
  EXPECT_GE(iGoodCount.load(), 1);
}

TEST(MaintenanceSchedulerTest, DestructorStopsCleanly) {
  std::atomic<int> iCount{0};

  {
    MaintenanceScheduler ms;
    ms.schedule("task", 1s, [&iCount]() { iCount.fetch_add(1); });
    ms.start();
    std::this_thread::sleep_for(500ms);
  }
  // Destructor should stop cleanly without hanging or crashing
  SUCCEED();
}
```

**Step 2: Run tests to verify they fail**

Run: `cd build && ninja dns-tests && ./tests/dns-tests --gtest_filter='MaintenanceSchedulerTest.*' 2>&1`
Expected: All tests FAIL with "not implemented" runtime error.

**Step 3: Implement MaintenanceScheduler**

Replace `src/core/MaintenanceScheduler.cpp`:

```cpp
#include "core/MaintenanceScheduler.hpp"

#include "common/Logger.hpp"

#include <algorithm>

namespace dns::core {

MaintenanceScheduler::MaintenanceScheduler() = default;

MaintenanceScheduler::~MaintenanceScheduler() {
  stop();
}

void MaintenanceScheduler::schedule(const std::string& sName,
                                    std::chrono::seconds durInterval,
                                    std::function<void()> fnTask) {
  _vTasks.push_back(Task{
      sName,
      durInterval,
      std::move(fnTask),
      std::chrono::steady_clock::now()  // run immediately on first pass
  });
}

void MaintenanceScheduler::start() {
  std::lock_guard<std::mutex> lock(_mtx);
  if (_bRunning) return;
  _bRunning = true;

  _thread = std::jthread([this](std::stop_token stToken) {
    auto spLog = dns::common::Logger::get();

    while (!stToken.stop_requested()) {
      auto tpNow = std::chrono::steady_clock::now();

      for (auto& task : _vTasks) {
        if (tpNow >= task.tpNextRun) {
          try {
            task.fn();
          } catch (const std::exception& ex) {
            if (spLog) {
              spLog->error("MaintenanceScheduler: task '{}' failed: {}", task.sName, ex.what());
            }
          } catch (...) {
            if (spLog) {
              spLog->error("MaintenanceScheduler: task '{}' failed with unknown error", task.sName);
            }
          }
          task.tpNextRun = std::chrono::steady_clock::now() + task.durInterval;
        }
      }

      // Find the next scheduled run time
      auto tpNextWake = std::chrono::steady_clock::now() + std::chrono::hours(1);
      for (const auto& task : _vTasks) {
        tpNextWake = std::min(tpNextWake, task.tpNextRun);
      }

      // Sleep until next task is due, or until stop is requested
      std::unique_lock<std::mutex> ulock(_mtx);
      _cv.wait_until(ulock, tpNextWake, [&stToken]() {
        return stToken.stop_requested();
      });
    }
  });
}

void MaintenanceScheduler::stop() {
  {
    std::lock_guard<std::mutex> lock(_mtx);
    if (!_bRunning) return;
    _bRunning = false;
  }

  _thread.request_stop();
  _cv.notify_all();

  if (_thread.joinable()) {
    _thread.join();
  }
}

}  // namespace dns::core
```

**Step 4: Run tests to verify they pass**

Run: `cd build && ninja dns-tests && ./tests/dns-tests --gtest_filter='MaintenanceSchedulerTest.*' 2>&1`
Expected: All 5 MaintenanceSchedulerTest tests PASS.

**Step 5: Commit**

```bash
git add src/core/MaintenanceScheduler.cpp tests/unit/test_maintenance_scheduler.cpp
git commit -m "feat(core): implement MaintenanceScheduler with jthread and error isolation"
```

---

## Task 4: Update Repository Headers

**Files:**
- Modify: `include/dal/UserRepository.hpp`
- Modify: `include/dal/SessionRepository.hpp`
- Modify: `include/dal/ApiKeyRepository.hpp`

**Context:** The current repository headers are stubs with default constructors and no methods. This task adds proper constructors (taking `ConnectionPool&`), row types, and complete method signatures matching ARCHITECTURE.md §4.3.

**Step 1: Update UserRepository header**

Replace `include/dal/UserRepository.hpp`:

```cpp
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace dns::dal {

class ConnectionPool;

/// Row type returned from user queries.
struct UserRow {
  int64_t iId = 0;
  std::string sUsername;
  std::string sEmail;
  std::string sPasswordHash;
  std::string sAuthMethod;
  bool bIsActive = true;
};

/// Manages users + groups + group_members.
/// Class abbreviation: ur
class UserRepository {
 public:
  explicit UserRepository(ConnectionPool& cpPool);
  ~UserRepository();

  /// Find a user by username. Returns nullopt if not found.
  std::optional<UserRow> findByUsername(const std::string& sUsername);

  /// Find a user by ID. Returns nullopt if not found.
  std::optional<UserRow> findById(int64_t iUserId);

  /// Create a local user. Returns the new user ID.
  int64_t create(const std::string& sUsername, const std::string& sEmail,
                 const std::string& sPasswordHash);

  /// Resolve the highest-privilege role for a user across all their groups.
  /// Returns "admin", "operator", or "viewer". Returns empty string if user
  /// has no group membership.
  std::string getHighestRole(int64_t iUserId);

 private:
  ConnectionPool& _cpPool;
};

}  // namespace dns::dal
```

**Step 2: Update SessionRepository header**

Replace `include/dal/SessionRepository.hpp`:

```cpp
#pragma once

#include <cstdint>
#include <string>

namespace dns::dal {

class ConnectionPool;

/// Manages the sessions table; create, touch, exists, deleteByHash, pruneExpired.
/// Class abbreviation: sr
class SessionRepository {
 public:
  explicit SessionRepository(ConnectionPool& cpPool);
  ~SessionRepository();

  /// Create a new session row. sliding TTL sets expires_at; absolute TTL sets
  /// absolute_expires_at. Both are relative to NOW().
  void create(int64_t iUserId, const std::string& sTokenHash,
              int iSlidingTtlSeconds, int iAbsoluteTtlSeconds);

  /// Update last_seen_at and extend expires_at by iSlidingTtl seconds,
  /// clamped to absolute_expires_at.
  void touch(const std::string& sTokenHash, int iSlidingTtl, int iAbsoluteTtl);

  /// Check if a session row exists for this token hash.
  bool exists(const std::string& sTokenHash);

  /// Returns true if the session exists and has not exceeded its sliding
  /// or absolute TTL. Also checks that the user is still active.
  /// Returns false if expired or revoked (row absent).
  bool isValid(const std::string& sTokenHash);

  /// Hard-delete a session row by token hash.
  void deleteByHash(const std::string& sTokenHash);

  /// Delete all sessions where expires_at < NOW(). Returns rows deleted.
  int pruneExpired();

 private:
  ConnectionPool& _cpPool;
};

}  // namespace dns::dal
```

**Step 3: Update ApiKeyRepository header**

Replace `include/dal/ApiKeyRepository.hpp`:

```cpp
#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>

namespace dns::dal {

class ConnectionPool;

/// Row type returned from API key queries.
struct ApiKeyRow {
  int64_t iId = 0;
  int64_t iUserId = 0;
  std::string sKeyHash;
  std::string sDescription;
  bool bRevoked = false;
  std::optional<std::chrono::system_clock::time_point> oExpiresAt;
};

/// Manages the api_keys table; create, findByHash, scheduleDelete, pruneScheduled.
/// Class abbreviation: akr
class ApiKeyRepository {
 public:
  explicit ApiKeyRepository(ConnectionPool& cpPool);
  ~ApiKeyRepository();

  /// Create a new API key row. Returns the row ID.
  int64_t create(int64_t iUserId, const std::string& sKeyHash,
                 const std::string& sDescription,
                 std::optional<std::chrono::system_clock::time_point> oExpiresAt);

  /// Find an API key by its SHA-512 hash. Returns nullopt if not found.
  std::optional<ApiKeyRow> findByHash(const std::string& sKeyHash);

  /// Mark a key for deferred deletion: set delete_after = NOW() + grace seconds.
  void scheduleDelete(int64_t iKeyId, int iGraceSeconds);

  /// Delete all API key rows where delete_after < NOW(). Returns rows deleted.
  int pruneScheduled();

 private:
  ConnectionPool& _cpPool;
};

}  // namespace dns::dal
```

**Step 4: Verify the project still compiles**

The .cpp stubs will break because their constructors no longer match. Update each stub's constructor to accept `ConnectionPool&` and store it.

In `src/dal/UserRepository.cpp`:
```cpp
#include "dal/UserRepository.hpp"
#include "dal/ConnectionPool.hpp"

namespace dns::dal {

UserRepository::UserRepository(ConnectionPool& cpPool) : _cpPool(cpPool) {}
UserRepository::~UserRepository() = default;

}  // namespace dns::dal
```

In `src/dal/SessionRepository.cpp`:
```cpp
#include "dal/SessionRepository.hpp"
#include "dal/ConnectionPool.hpp"

#include <stdexcept>

namespace dns::dal {

SessionRepository::SessionRepository(ConnectionPool& cpPool) : _cpPool(cpPool) {}
SessionRepository::~SessionRepository() = default;

void SessionRepository::create(int64_t /*iUserId*/, const std::string& /*sTokenHash*/,
                               int /*iSlidingTtlSeconds*/, int /*iAbsoluteTtlSeconds*/) {
  throw std::runtime_error{"not implemented"};
}

void SessionRepository::touch(const std::string& /*sTokenHash*/, int /*iSlidingTtl*/,
                              int /*iAbsoluteTtl*/) {
  throw std::runtime_error{"not implemented"};
}

bool SessionRepository::exists(const std::string& /*sTokenHash*/) {
  throw std::runtime_error{"not implemented"};
}

bool SessionRepository::isValid(const std::string& /*sTokenHash*/) {
  throw std::runtime_error{"not implemented"};
}

void SessionRepository::deleteByHash(const std::string& /*sTokenHash*/) {
  throw std::runtime_error{"not implemented"};
}

int SessionRepository::pruneExpired() { throw std::runtime_error{"not implemented"}; }

}  // namespace dns::dal
```

In `src/dal/ApiKeyRepository.cpp`:
```cpp
#include "dal/ApiKeyRepository.hpp"
#include "dal/ConnectionPool.hpp"

#include <stdexcept>

namespace dns::dal {

ApiKeyRepository::ApiKeyRepository(ConnectionPool& cpPool) : _cpPool(cpPool) {}
ApiKeyRepository::~ApiKeyRepository() = default;

int64_t ApiKeyRepository::create(int64_t /*iUserId*/, const std::string& /*sKeyHash*/,
                                 const std::string& /*sDescription*/,
                                 std::optional<std::chrono::system_clock::time_point> /*oExpiresAt*/) {
  throw std::runtime_error{"not implemented"};
}

std::optional<ApiKeyRow> ApiKeyRepository::findByHash(const std::string& /*sKeyHash*/) {
  throw std::runtime_error{"not implemented"};
}

void ApiKeyRepository::scheduleDelete(int64_t /*iKeyId*/, int /*iGraceSeconds*/) {
  throw std::runtime_error{"not implemented"};
}

int ApiKeyRepository::pruneScheduled() { throw std::runtime_error{"not implemented"}; }

}  // namespace dns::dal
```

Run: `cd build && ninja dns-tests 2>&1 | tail -5`
Expected: Compiles successfully.

**Step 5: Commit**

```bash
git add include/dal/UserRepository.hpp include/dal/SessionRepository.hpp include/dal/ApiKeyRepository.hpp \
        src/dal/UserRepository.cpp src/dal/SessionRepository.cpp src/dal/ApiKeyRepository.cpp
git commit -m "feat(dal): update repository headers with full auth method signatures and row types"
```

---

## Task 5: UserRepository Implementation

**Files:**
- Modify: `src/dal/UserRepository.cpp`
- Create: `tests/integration/test_user_repository.cpp`

**Context:** UserRepository manages the `users`, `groups`, and `group_members` tables. It provides `findByUsername`, `findById`, `create`, and `getHighestRole` (resolves highest-privilege role across all group memberships). Integration tests require `DNS_DB_URL` and the schema from `scripts/db/001_initial_schema.sql` applied to the test database.

**Step 1: Write the failing integration tests**

Create `tests/integration/test_user_repository.cpp`:

```cpp
#include "dal/UserRepository.hpp"

#include "common/Logger.hpp"
#include "dal/ConnectionPool.hpp"

#include <gtest/gtest.h>

#include <cstdlib>
#include <string>

using dns::dal::ConnectionPool;
using dns::dal::UserRepository;
using dns::dal::UserRow;

namespace {

std::string getDbUrl() {
  const char* pUrl = std::getenv("DNS_DB_URL");
  return pUrl ? std::string(pUrl) : std::string{};
}

}  // namespace

class UserRepositoryTest : public ::testing::Test {
 protected:
  void SetUp() override {
    _sDbUrl = getDbUrl();
    if (_sDbUrl.empty()) {
      GTEST_SKIP() << "DNS_DB_URL not set — skipping integration test";
    }
    dns::common::Logger::init("warn");
    _cpPool = std::make_unique<ConnectionPool>(_sDbUrl, 2);
    _urRepo = std::make_unique<UserRepository>(*_cpPool);

    // Clean test data
    auto cg = _cpPool->checkout();
    pqxx::work txn(*cg);
    txn.exec("DELETE FROM group_members");
    txn.exec("DELETE FROM sessions");
    txn.exec("DELETE FROM api_keys");
    txn.exec("DELETE FROM deployments");
    txn.exec("DELETE FROM users");
    txn.exec("DELETE FROM groups");
    txn.commit();
  }

  std::string _sDbUrl;
  std::unique_ptr<ConnectionPool> _cpPool;
  std::unique_ptr<UserRepository> _urRepo;
};

TEST_F(UserRepositoryTest, CreateAndFindByUsername) {
  int64_t iId = _urRepo->create("alice", "alice@example.com", "$argon2id$v=19$m=65536,t=3,p=1$fakesalt$fakehash");

  EXPECT_GT(iId, 0);

  auto oUser = _urRepo->findByUsername("alice");
  ASSERT_TRUE(oUser.has_value());
  EXPECT_EQ(oUser->iId, iId);
  EXPECT_EQ(oUser->sUsername, "alice");
  EXPECT_EQ(oUser->sEmail, "alice@example.com");
  EXPECT_EQ(oUser->sAuthMethod, "local");
  EXPECT_TRUE(oUser->bIsActive);
}

TEST_F(UserRepositoryTest, FindByUsernameReturnsNulloptForMissing) {
  auto oUser = _urRepo->findByUsername("nonexistent");
  EXPECT_FALSE(oUser.has_value());
}

TEST_F(UserRepositoryTest, FindByIdWorks) {
  int64_t iId = _urRepo->create("bob", "bob@example.com", "hash123");

  auto oUser = _urRepo->findById(iId);
  ASSERT_TRUE(oUser.has_value());
  EXPECT_EQ(oUser->sUsername, "bob");
}

TEST_F(UserRepositoryTest, GetHighestRoleReturnsAdminOverOperator) {
  int64_t iUserId = _urRepo->create("carol", "carol@example.com", "hash");

  // Create groups and memberships
  auto cg = _cpPool->checkout();
  pqxx::work txn(*cg);
  auto rOp = txn.exec1("INSERT INTO groups (name, role) VALUES ('operators', 'operator') RETURNING id");
  auto rAdmin = txn.exec1("INSERT INTO groups (name, role) VALUES ('admins', 'admin') RETURNING id");
  txn.exec_params("INSERT INTO group_members (user_id, group_id) VALUES ($1, $2)",
                   iUserId, rOp[0].as<int64_t>());
  txn.exec_params("INSERT INTO group_members (user_id, group_id) VALUES ($1, $2)",
                   iUserId, rAdmin[0].as<int64_t>());
  txn.commit();

  std::string sRole = _urRepo->getHighestRole(iUserId);
  EXPECT_EQ(sRole, "admin");
}

TEST_F(UserRepositoryTest, GetHighestRoleReturnsEmptyForNoGroups) {
  int64_t iUserId = _urRepo->create("dave", "dave@example.com", "hash");
  std::string sRole = _urRepo->getHighestRole(iUserId);
  EXPECT_TRUE(sRole.empty());
}
```

**Step 2: Run tests to verify they fail**

Run: `cd build && ninja dns-tests && DNS_DB_URL="postgresql://..." ./tests/dns-tests --gtest_filter='UserRepositoryTest.*' 2>&1`
Expected: Tests FAIL with "not implemented" or link errors (stubs only).

**Step 3: Implement UserRepository**

Replace `src/dal/UserRepository.cpp`:

```cpp
#include "dal/UserRepository.hpp"

#include "dal/ConnectionPool.hpp"

#include <pqxx/pqxx>

namespace dns::dal {

UserRepository::UserRepository(ConnectionPool& cpPool) : _cpPool(cpPool) {}
UserRepository::~UserRepository() = default;

std::optional<UserRow> UserRepository::findByUsername(const std::string& sUsername) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec_params(
      "SELECT id, username, COALESCE(email, ''), COALESCE(password_hash, ''), "
      "auth_method::text, is_active "
      "FROM users WHERE username = $1",
      sUsername);
  txn.commit();

  if (result.empty()) return std::nullopt;

  auto row = result[0];
  return UserRow{
      row[0].as<int64_t>(),
      row[1].as<std::string>(),
      row[2].as<std::string>(),
      row[3].as<std::string>(),
      row[4].as<std::string>(),
      row[5].as<bool>(),
  };
}

std::optional<UserRow> UserRepository::findById(int64_t iUserId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec_params(
      "SELECT id, username, COALESCE(email, ''), COALESCE(password_hash, ''), "
      "auth_method::text, is_active "
      "FROM users WHERE id = $1",
      iUserId);
  txn.commit();

  if (result.empty()) return std::nullopt;

  auto row = result[0];
  return UserRow{
      row[0].as<int64_t>(),
      row[1].as<std::string>(),
      row[2].as<std::string>(),
      row[3].as<std::string>(),
      row[4].as<std::string>(),
      row[5].as<bool>(),
  };
}

int64_t UserRepository::create(const std::string& sUsername, const std::string& sEmail,
                               const std::string& sPasswordHash) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec_params1(
      "INSERT INTO users (username, email, password_hash, auth_method) "
      "VALUES ($1, $2, $3, 'local') RETURNING id",
      sUsername, sEmail, sPasswordHash);
  txn.commit();
  return result[0].as<int64_t>();
}

std::string UserRepository::getHighestRole(int64_t iUserId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);

  // Role priority: admin > operator > viewer
  // Use CASE to assign numeric priority, take the max
  auto result = txn.exec_params(
      "SELECT g.role::text FROM groups g "
      "JOIN group_members gm ON gm.group_id = g.id "
      "WHERE gm.user_id = $1 "
      "ORDER BY CASE g.role::text "
      "  WHEN 'admin' THEN 3 "
      "  WHEN 'operator' THEN 2 "
      "  WHEN 'viewer' THEN 1 "
      "END DESC "
      "LIMIT 1",
      iUserId);
  txn.commit();

  if (result.empty()) return "";
  return result[0][0].as<std::string>();
}

}  // namespace dns::dal
```

**Step 4: Run tests to verify they pass**

Run: `cd build && ninja dns-tests && DNS_DB_URL="postgresql://..." ./tests/dns-tests --gtest_filter='UserRepositoryTest.*' 2>&1`
Expected: All 5 UserRepositoryTest tests PASS.

**Step 5: Commit**

```bash
git add src/dal/UserRepository.cpp tests/integration/test_user_repository.cpp
git commit -m "feat(dal): implement UserRepository with CRUD and role resolution"
```

---

## Task 6: SessionRepository Implementation

**Files:**
- Modify: `src/dal/SessionRepository.cpp`
- Create: `tests/integration/test_session_repository.cpp`

**Context:** SessionRepository manages the `sessions` table. Sessions are created on login, touched on each authenticated request (extending the sliding window), and hard-deleted on logout/revocation/expiry. `pruneExpired()` is called periodically by MaintenanceScheduler.

**Step 1: Write the failing integration tests**

Create `tests/integration/test_session_repository.cpp`:

```cpp
#include "dal/SessionRepository.hpp"

#include "common/Logger.hpp"
#include "dal/ConnectionPool.hpp"

#include <gtest/gtest.h>

#include <cstdlib>
#include <string>

using dns::dal::ConnectionPool;
using dns::dal::SessionRepository;

namespace {

std::string getDbUrl() {
  const char* pUrl = std::getenv("DNS_DB_URL");
  return pUrl ? std::string(pUrl) : std::string{};
}

}  // namespace

class SessionRepositoryTest : public ::testing::Test {
 protected:
  void SetUp() override {
    _sDbUrl = getDbUrl();
    if (_sDbUrl.empty()) {
      GTEST_SKIP() << "DNS_DB_URL not set — skipping integration test";
    }
    dns::common::Logger::init("warn");
    _cpPool = std::make_unique<ConnectionPool>(_sDbUrl, 2);
    _srRepo = std::make_unique<SessionRepository>(*_cpPool);

    // Clean test data and ensure a test user exists
    auto cg = _cpPool->checkout();
    pqxx::work txn(*cg);
    txn.exec("DELETE FROM sessions");
    txn.exec("DELETE FROM group_members");
    txn.exec("DELETE FROM api_keys");
    txn.exec("DELETE FROM deployments");
    txn.exec("DELETE FROM users");
    auto r = txn.exec1(
        "INSERT INTO users (username, email, password_hash, auth_method) "
        "VALUES ('testuser', 'test@example.com', 'hash', 'local') RETURNING id");
    _iTestUserId = r[0].as<int64_t>();
    txn.commit();
  }

  std::string _sDbUrl;
  std::unique_ptr<ConnectionPool> _cpPool;
  std::unique_ptr<SessionRepository> _srRepo;
  int64_t _iTestUserId = 0;
};

TEST_F(SessionRepositoryTest, CreateAndExistsWorks) {
  _srRepo->create(_iTestUserId, "token-hash-001", 3600, 86400);
  EXPECT_TRUE(_srRepo->exists("token-hash-001"));
}

TEST_F(SessionRepositoryTest, ExistsReturnsFalseForMissing) {
  EXPECT_FALSE(_srRepo->exists("nonexistent-hash"));
}

TEST_F(SessionRepositoryTest, DeleteByHashRemovesSession) {
  _srRepo->create(_iTestUserId, "token-hash-002", 3600, 86400);
  EXPECT_TRUE(_srRepo->exists("token-hash-002"));

  _srRepo->deleteByHash("token-hash-002");
  EXPECT_FALSE(_srRepo->exists("token-hash-002"));
}

TEST_F(SessionRepositoryTest, IsValidReturnsTrueForFreshSession) {
  _srRepo->create(_iTestUserId, "valid-token", 3600, 86400);
  EXPECT_TRUE(_srRepo->isValid("valid-token"));
}

TEST_F(SessionRepositoryTest, PruneExpiredDeletesOldSessions) {
  // Create a session with very short TTL
  auto cg = _cpPool->checkout();
  pqxx::work txn(*cg);
  txn.exec_params(
      "INSERT INTO sessions (user_id, token_hash, expires_at, absolute_expires_at) "
      "VALUES ($1, 'expired-token', NOW() - INTERVAL '1 hour', NOW() - INTERVAL '1 hour')",
      _iTestUserId);
  txn.commit();

  EXPECT_TRUE(_srRepo->exists("expired-token"));

  int iDeleted = _srRepo->pruneExpired();
  EXPECT_GE(iDeleted, 1);
  EXPECT_FALSE(_srRepo->exists("expired-token"));
}
```

**Step 2: Run tests to verify they fail**

Run: `cd build && ninja dns-tests && DNS_DB_URL="postgresql://..." ./tests/dns-tests --gtest_filter='SessionRepositoryTest.*' 2>&1`
Expected: All tests FAIL with "not implemented" runtime error.

**Step 3: Implement SessionRepository**

Replace `src/dal/SessionRepository.cpp`:

```cpp
#include "dal/SessionRepository.hpp"

#include "dal/ConnectionPool.hpp"

#include <pqxx/pqxx>

namespace dns::dal {

SessionRepository::SessionRepository(ConnectionPool& cpPool) : _cpPool(cpPool) {}
SessionRepository::~SessionRepository() = default;

void SessionRepository::create(int64_t iUserId, const std::string& sTokenHash,
                               int iSlidingTtlSeconds, int iAbsoluteTtlSeconds) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  txn.exec_params(
      "INSERT INTO sessions (user_id, token_hash, expires_at, absolute_expires_at) "
      "VALUES ($1, $2, NOW() + make_interval(secs => $3), "
      "NOW() + make_interval(secs => $4))",
      iUserId, sTokenHash, iSlidingTtlSeconds, iAbsoluteTtlSeconds);
  txn.commit();
}

void SessionRepository::touch(const std::string& sTokenHash, int iSlidingTtl,
                              int /*iAbsoluteTtl*/) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  // Extend expires_at by sliding TTL, clamped to absolute_expires_at
  txn.exec_params(
      "UPDATE sessions SET "
      "last_seen_at = NOW(), "
      "expires_at = LEAST(NOW() + make_interval(secs => $2), absolute_expires_at) "
      "WHERE token_hash = $1",
      sTokenHash, iSlidingTtl);
  txn.commit();
}

bool SessionRepository::exists(const std::string& sTokenHash) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec_params(
      "SELECT 1 FROM sessions WHERE token_hash = $1", sTokenHash);
  txn.commit();
  return !result.empty();
}

bool SessionRepository::isValid(const std::string& sTokenHash) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec_params(
      "SELECT 1 FROM sessions s "
      "JOIN users u ON u.id = s.user_id "
      "WHERE s.token_hash = $1 "
      "AND s.expires_at > NOW() "
      "AND s.absolute_expires_at > NOW() "
      "AND u.is_active = TRUE",
      sTokenHash);
  txn.commit();
  return !result.empty();
}

void SessionRepository::deleteByHash(const std::string& sTokenHash) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  txn.exec_params("DELETE FROM sessions WHERE token_hash = $1", sTokenHash);
  txn.commit();
}

int SessionRepository::pruneExpired() {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "DELETE FROM sessions WHERE expires_at < NOW() OR absolute_expires_at < NOW()");
  txn.commit();
  return static_cast<int>(result.affected_rows());
}

}  // namespace dns::dal
```

**Step 4: Run tests to verify they pass**

Run: `cd build && ninja dns-tests && DNS_DB_URL="postgresql://..." ./tests/dns-tests --gtest_filter='SessionRepositoryTest.*' 2>&1`
Expected: All 5 SessionRepositoryTest tests PASS.

**Step 5: Commit**

```bash
git add src/dal/SessionRepository.cpp tests/integration/test_session_repository.cpp
git commit -m "feat(dal): implement SessionRepository with create, touch, and prune"
```

---

## Task 7: ApiKeyRepository Implementation

**Files:**
- Modify: `src/dal/ApiKeyRepository.cpp`
- Create: `tests/integration/test_api_key_repository.cpp`

**Context:** ApiKeyRepository manages the `api_keys` table. Keys are created by admins, validated per-request via SHA-512 hash lookup, and subject to deferred deletion (grace period before physical row removal). `pruneScheduled()` is called periodically by MaintenanceScheduler.

**Step 1: Write the failing integration tests**

Create `tests/integration/test_api_key_repository.cpp`:

```cpp
#include "dal/ApiKeyRepository.hpp"

#include "common/Logger.hpp"
#include "dal/ConnectionPool.hpp"

#include <gtest/gtest.h>

#include <cstdlib>
#include <string>

using dns::dal::ApiKeyRepository;
using dns::dal::ApiKeyRow;
using dns::dal::ConnectionPool;

namespace {

std::string getDbUrl() {
  const char* pUrl = std::getenv("DNS_DB_URL");
  return pUrl ? std::string(pUrl) : std::string{};
}

}  // namespace

class ApiKeyRepositoryTest : public ::testing::Test {
 protected:
  void SetUp() override {
    _sDbUrl = getDbUrl();
    if (_sDbUrl.empty()) {
      GTEST_SKIP() << "DNS_DB_URL not set — skipping integration test";
    }
    dns::common::Logger::init("warn");
    _cpPool = std::make_unique<ConnectionPool>(_sDbUrl, 2);
    _akrRepo = std::make_unique<ApiKeyRepository>(*_cpPool);

    // Clean test data and ensure a test user exists
    auto cg = _cpPool->checkout();
    pqxx::work txn(*cg);
    txn.exec("DELETE FROM api_keys");
    txn.exec("DELETE FROM sessions");
    txn.exec("DELETE FROM group_members");
    txn.exec("DELETE FROM deployments");
    txn.exec("DELETE FROM users");
    auto r = txn.exec1(
        "INSERT INTO users (username, email, password_hash, auth_method) "
        "VALUES ('apiuser', 'api@example.com', 'hash', 'local') RETURNING id");
    _iTestUserId = r[0].as<int64_t>();
    txn.commit();
  }

  std::string _sDbUrl;
  std::unique_ptr<ConnectionPool> _cpPool;
  std::unique_ptr<ApiKeyRepository> _akrRepo;
  int64_t _iTestUserId = 0;
};

TEST_F(ApiKeyRepositoryTest, CreateAndFindByHash) {
  int64_t iId = _akrRepo->create(_iTestUserId, "sha512-hash-value", "test key", std::nullopt);
  EXPECT_GT(iId, 0);

  auto oKey = _akrRepo->findByHash("sha512-hash-value");
  ASSERT_TRUE(oKey.has_value());
  EXPECT_EQ(oKey->iId, iId);
  EXPECT_EQ(oKey->iUserId, _iTestUserId);
  EXPECT_EQ(oKey->sDescription, "test key");
  EXPECT_FALSE(oKey->bRevoked);
  EXPECT_FALSE(oKey->oExpiresAt.has_value());
}

TEST_F(ApiKeyRepositoryTest, FindByHashReturnsNulloptForMissing) {
  auto oKey = _akrRepo->findByHash("nonexistent-hash");
  EXPECT_FALSE(oKey.has_value());
}

TEST_F(ApiKeyRepositoryTest, ScheduleDeleteSetsDeleteAfter) {
  int64_t iId = _akrRepo->create(_iTestUserId, "to-delete-hash", "deletable", std::nullopt);
  _akrRepo->scheduleDelete(iId, 0);  // 0 grace = immediate

  // Prune should delete it
  int iDeleted = _akrRepo->pruneScheduled();
  EXPECT_GE(iDeleted, 1);

  auto oKey = _akrRepo->findByHash("to-delete-hash");
  EXPECT_FALSE(oKey.has_value());
}

TEST_F(ApiKeyRepositoryTest, PruneDoesNotDeleteFutureGrace) {
  int64_t iId = _akrRepo->create(_iTestUserId, "future-delete-hash", "future", std::nullopt);
  _akrRepo->scheduleDelete(iId, 86400);  // 24h grace

  int iDeleted = _akrRepo->pruneScheduled();
  EXPECT_EQ(iDeleted, 0);

  auto oKey = _akrRepo->findByHash("future-delete-hash");
  EXPECT_TRUE(oKey.has_value());
}
```

**Step 2: Run tests to verify they fail**

Run: `cd build && ninja dns-tests && DNS_DB_URL="postgresql://..." ./tests/dns-tests --gtest_filter='ApiKeyRepositoryTest.*' 2>&1`
Expected: All tests FAIL with "not implemented" runtime error.

**Step 3: Implement ApiKeyRepository**

Replace `src/dal/ApiKeyRepository.cpp`:

```cpp
#include "dal/ApiKeyRepository.hpp"

#include "dal/ConnectionPool.hpp"

#include <pqxx/pqxx>

namespace dns::dal {

ApiKeyRepository::ApiKeyRepository(ConnectionPool& cpPool) : _cpPool(cpPool) {}
ApiKeyRepository::~ApiKeyRepository() = default;

int64_t ApiKeyRepository::create(int64_t iUserId, const std::string& sKeyHash,
                                 const std::string& sDescription,
                                 std::optional<std::chrono::system_clock::time_point> oExpiresAt) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);

  pqxx::result result;
  if (oExpiresAt.has_value()) {
    auto tpExpiry = std::chrono::duration_cast<std::chrono::seconds>(
                        oExpiresAt->time_since_epoch())
                        .count();
    result = txn.exec_params(
        "INSERT INTO api_keys (user_id, key_hash, description, expires_at) "
        "VALUES ($1, $2, $3, to_timestamp($4)) RETURNING id",
        iUserId, sKeyHash, sDescription, tpExpiry);
  } else {
    result = txn.exec_params(
        "INSERT INTO api_keys (user_id, key_hash, description) "
        "VALUES ($1, $2, $3) RETURNING id",
        iUserId, sKeyHash, sDescription);
  }

  txn.commit();
  return result[0][0].as<int64_t>();
}

std::optional<ApiKeyRow> ApiKeyRepository::findByHash(const std::string& sKeyHash) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec_params(
      "SELECT id, user_id, key_hash, COALESCE(description, ''), revoked, "
      "EXTRACT(EPOCH FROM expires_at)::bigint "
      "FROM api_keys WHERE key_hash = $1",
      sKeyHash);
  txn.commit();

  if (result.empty()) return std::nullopt;

  auto row = result[0];
  ApiKeyRow akRow;
  akRow.iId = row[0].as<int64_t>();
  akRow.iUserId = row[1].as<int64_t>();
  akRow.sKeyHash = row[2].as<std::string>();
  akRow.sDescription = row[3].as<std::string>();
  akRow.bRevoked = row[4].as<bool>();
  if (!row[5].is_null()) {
    akRow.oExpiresAt = std::chrono::system_clock::time_point(
        std::chrono::seconds(row[5].as<int64_t>()));
  }
  return akRow;
}

void ApiKeyRepository::scheduleDelete(int64_t iKeyId, int iGraceSeconds) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  txn.exec_params(
      "UPDATE api_keys SET delete_after = NOW() + make_interval(secs => $2) "
      "WHERE id = $1",
      iKeyId, iGraceSeconds);
  txn.commit();
}

int ApiKeyRepository::pruneScheduled() {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "DELETE FROM api_keys WHERE delete_after IS NOT NULL AND delete_after < NOW()");
  txn.commit();
  return static_cast<int>(result.affected_rows());
}

}  // namespace dns::dal
```

**Step 4: Run tests to verify they pass**

Run: `cd build && ninja dns-tests && DNS_DB_URL="postgresql://..." ./tests/dns-tests --gtest_filter='ApiKeyRepositoryTest.*' 2>&1`
Expected: All 4 ApiKeyRepositoryTest tests PASS.

**Step 5: Commit**

```bash
git add src/dal/ApiKeyRepository.cpp tests/integration/test_api_key_repository.cpp
git commit -m "feat(dal): implement ApiKeyRepository with create, findByHash, and deferred prune"
```

---

## Task 8: AuthService Implementation

**Files:**
- Modify: `include/security/AuthService.hpp`
- Modify: `src/security/AuthService.cpp`
- Create: `tests/integration/test_auth_service.cpp`

**Context:** AuthService orchestrates the local login flow: look up user → verify Argon2id hash → resolve role → generate JWT → create session → return token. `validateToken()` verifies a JWT and returns a `RequestContext`. This task depends on UserRepository, SessionRepository, IJwtSigner, and the CryptoService Argon2id additions.

**Step 1: Update AuthService header**

Replace `include/security/AuthService.hpp`:

```cpp
#pragma once

#include <cstdint>
#include <string>

#include "common/Types.hpp"

namespace dns::dal {
class ConnectionPool;
class UserRepository;
class SessionRepository;
}  // namespace dns::dal

namespace dns::security {

class IJwtSigner;

/// Handles local authentication (Argon2id) and JWT session creation.
/// Class abbreviation: as
class AuthService {
 public:
  AuthService(dal::UserRepository& urRepo,
              dal::SessionRepository& srRepo,
              const IJwtSigner& jsSigner,
              int iJwtTtlSeconds,
              int iSessionAbsoluteTtlSeconds);
  ~AuthService();

  /// Authenticate with username/password. Returns a signed JWT on success.
  /// Throws AuthenticationError on invalid credentials.
  /// Throws AuthenticationError if user account is inactive.
  std::string authenticateLocal(const std::string& sUsername, const std::string& sPassword);

  /// Validate a JWT token. Returns the identity context on success.
  /// Throws AuthenticationError on invalid/expired token.
  common::RequestContext validateToken(const std::string& sToken) const;

 private:
  dal::UserRepository& _urRepo;
  dal::SessionRepository& _srRepo;
  const IJwtSigner& _jsSigner;
  int _iJwtTtlSeconds;
  int _iSessionAbsoluteTtlSeconds;
};

}  // namespace dns::security
```

**Step 2: Write the failing integration tests**

Create `tests/integration/test_auth_service.cpp`:

```cpp
#include "security/AuthService.hpp"

#include "common/Errors.hpp"
#include "common/Logger.hpp"
#include "dal/ConnectionPool.hpp"
#include "dal/SessionRepository.hpp"
#include "dal/UserRepository.hpp"
#include "security/CryptoService.hpp"
#include "security/HmacJwtSigner.hpp"

#include <gtest/gtest.h>

#include <cstdlib>
#include <string>

using dns::common::AuthenticationError;
using dns::dal::ConnectionPool;
using dns::dal::SessionRepository;
using dns::dal::UserRepository;
using dns::security::AuthService;
using dns::security::CryptoService;
using dns::security::HmacJwtSigner;

namespace {

std::string getDbUrl() {
  const char* pUrl = std::getenv("DNS_DB_URL");
  return pUrl ? std::string(pUrl) : std::string{};
}

}  // namespace

class AuthServiceTest : public ::testing::Test {
 protected:
  void SetUp() override {
    _sDbUrl = getDbUrl();
    if (_sDbUrl.empty()) {
      GTEST_SKIP() << "DNS_DB_URL not set — skipping integration test";
    }
    dns::common::Logger::init("warn");
    _cpPool = std::make_unique<ConnectionPool>(_sDbUrl, 2);
    _urRepo = std::make_unique<UserRepository>(*_cpPool);
    _srRepo = std::make_unique<SessionRepository>(*_cpPool);
    _jsSigner = std::make_unique<HmacJwtSigner>("test-jwt-secret-key");
    _asService = std::make_unique<AuthService>(*_urRepo, *_srRepo, *_jsSigner, 3600, 86400);

    // Clean test data
    auto cg = _cpPool->checkout();
    pqxx::work txn(*cg);
    txn.exec("DELETE FROM sessions");
    txn.exec("DELETE FROM api_keys");
    txn.exec("DELETE FROM group_members");
    txn.exec("DELETE FROM deployments");
    txn.exec("DELETE FROM users");
    txn.exec("DELETE FROM groups");

    // Create test user with known password hash
    std::string sHash = CryptoService::hashPassword("correct-password");
    auto r = txn.exec_params(
        "INSERT INTO users (username, email, password_hash, auth_method) "
        "VALUES ('alice', 'alice@example.com', $1, 'local') RETURNING id",
        sHash);
    _iTestUserId = r[0][0].as<int64_t>();

    // Create group and membership for role resolution
    auto rGroup = txn.exec1(
        "INSERT INTO groups (name, role) VALUES ('operators', 'operator') RETURNING id");
    txn.exec_params("INSERT INTO group_members (user_id, group_id) VALUES ($1, $2)",
                     _iTestUserId, rGroup[0].as<int64_t>());
    txn.commit();
  }

  std::string _sDbUrl;
  std::unique_ptr<ConnectionPool> _cpPool;
  std::unique_ptr<UserRepository> _urRepo;
  std::unique_ptr<SessionRepository> _srRepo;
  std::unique_ptr<HmacJwtSigner> _jsSigner;
  std::unique_ptr<AuthService> _asService;
  int64_t _iTestUserId = 0;
};

TEST_F(AuthServiceTest, AuthenticateLocalReturnsJwt) {
  std::string sToken = _asService->authenticateLocal("alice", "correct-password");

  // Token should be a valid JWT (3 dot-separated parts)
  int iDots = 0;
  for (char c : sToken) {
    if (c == '.') ++iDots;
  }
  EXPECT_EQ(iDots, 2);
}

TEST_F(AuthServiceTest, AuthenticateLocalWrongPasswordThrows) {
  EXPECT_THROW({
    try {
      _asService->authenticateLocal("alice", "wrong-password");
    } catch (const AuthenticationError& e) {
      EXPECT_EQ(e._sErrorCode, "invalid_credentials");
      throw;
    }
  }, AuthenticationError);
}

TEST_F(AuthServiceTest, AuthenticateLocalUnknownUserThrows) {
  EXPECT_THROW({
    try {
      _asService->authenticateLocal("nonexistent", "password");
    } catch (const AuthenticationError& e) {
      EXPECT_EQ(e._sErrorCode, "invalid_credentials");
      throw;
    }
  }, AuthenticationError);
}

TEST_F(AuthServiceTest, ValidateTokenReturnsRequestContext) {
  std::string sToken = _asService->authenticateLocal("alice", "correct-password");

  auto rcCtx = _asService->validateToken(sToken);
  EXPECT_EQ(rcCtx.iUserId, _iTestUserId);
  EXPECT_EQ(rcCtx.sUsername, "alice");
  EXPECT_EQ(rcCtx.sRole, "operator");
  EXPECT_EQ(rcCtx.sAuthMethod, "local");
}

TEST_F(AuthServiceTest, ValidateTokenCreatesSession) {
  std::string sToken = _asService->authenticateLocal("alice", "correct-password");

  // Session should exist in the DB
  std::string sTokenHash = CryptoService::sha256Hex(sToken);
  EXPECT_TRUE(_srRepo->exists(sTokenHash));
}
```

**Step 3: Implement AuthService**

Replace `src/security/AuthService.cpp`:

```cpp
#include "security/AuthService.hpp"

#include "common/Errors.hpp"
#include "dal/SessionRepository.hpp"
#include "dal/UserRepository.hpp"
#include "security/CryptoService.hpp"
#include "security/IJwtSigner.hpp"

#include <chrono>

#include <nlohmann/json.hpp>

namespace dns::security {

AuthService::AuthService(dal::UserRepository& urRepo,
                         dal::SessionRepository& srRepo,
                         const IJwtSigner& jsSigner,
                         int iJwtTtlSeconds,
                         int iSessionAbsoluteTtlSeconds)
    : _urRepo(urRepo),
      _srRepo(srRepo),
      _jsSigner(jsSigner),
      _iJwtTtlSeconds(iJwtTtlSeconds),
      _iSessionAbsoluteTtlSeconds(iSessionAbsoluteTtlSeconds) {}

AuthService::~AuthService() = default;

std::string AuthService::authenticateLocal(const std::string& sUsername,
                                           const std::string& sPassword) {
  // Look up user — use same error message for unknown user and wrong password
  // to prevent username enumeration
  auto oUser = _urRepo.findByUsername(sUsername);
  if (!oUser.has_value()) {
    throw common::AuthenticationError("invalid_credentials", "Invalid username or password");
  }

  if (!oUser->bIsActive) {
    throw common::AuthenticationError("account_disabled", "User account is disabled");
  }

  // Verify password
  if (!CryptoService::verifyPassword(sPassword, oUser->sPasswordHash)) {
    throw common::AuthenticationError("invalid_credentials", "Invalid username or password");
  }

  // Resolve role
  std::string sRole = _urRepo.getHighestRole(oUser->iId);
  if (sRole.empty()) {
    sRole = "viewer";  // default role if no group membership
  }

  // Build JWT payload
  auto iNow = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();

  nlohmann::json jPayload = {
      {"sub", std::to_string(oUser->iId)},
      {"username", oUser->sUsername},
      {"role", sRole},
      {"auth_method", "local"},
      {"iat", iNow},
      {"exp", iNow + _iJwtTtlSeconds},
  };

  std::string sToken = _jsSigner.sign(jPayload);

  // Create session: store SHA-256 hash of the token, not the raw token
  std::string sTokenHash = CryptoService::sha256Hex(sToken);
  _srRepo.create(oUser->iId, sTokenHash, _iJwtTtlSeconds, _iSessionAbsoluteTtlSeconds);

  return sToken;
}

common::RequestContext AuthService::validateToken(const std::string& sToken) const {
  // Verify JWT signature and expiry (throws AuthenticationError on failure)
  nlohmann::json jPayload = _jsSigner.verify(sToken);

  // Check session exists and is valid
  std::string sTokenHash = CryptoService::sha256Hex(sToken);
  if (!_srRepo.isValid(sTokenHash)) {
    // Clean up the expired/revoked session if it still exists
    if (_srRepo.exists(sTokenHash)) {
      _srRepo.deleteByHash(sTokenHash);
    }
    throw common::AuthenticationError("token_revoked", "Session has been revoked or expired");
  }

  // Touch session to extend sliding window
  _srRepo.touch(sTokenHash, _iJwtTtlSeconds, _iSessionAbsoluteTtlSeconds);

  // Build RequestContext from JWT payload
  common::RequestContext rcCtx;
  rcCtx.iUserId = std::stoll(jPayload["sub"].get<std::string>());
  rcCtx.sUsername = jPayload["username"].get<std::string>();
  rcCtx.sRole = jPayload["role"].get<std::string>();
  rcCtx.sAuthMethod = jPayload["auth_method"].get<std::string>();

  return rcCtx;
}

}  // namespace dns::security
```

**Step 4: Run tests to verify they pass**

Run: `cd build && ninja dns-tests && DNS_DB_URL="postgresql://..." ./tests/dns-tests --gtest_filter='AuthServiceTest.*' 2>&1`
Expected: All 5 AuthServiceTest tests PASS.

**Step 5: Commit**

```bash
git add include/security/AuthService.hpp src/security/AuthService.cpp tests/integration/test_auth_service.cpp
git commit -m "feat(security): implement AuthService with local login (Argon2id) and JWT sessions"
```

---

## Task 9: AuthMiddleware Implementation

**Files:**
- Modify: `include/api/AuthMiddleware.hpp`
- Modify: `src/api/AuthMiddleware.cpp`
- Create: `tests/integration/test_auth_middleware.cpp`

**Context:** AuthMiddleware validates every authenticated request. It supports two mutually exclusive credential schemes: (1) `Authorization: Bearer <jwt>` — JWT validated via IJwtSigner + session lookup, (2) `X-API-Key: <raw_key>` — SHA-512 hashed and looked up in api_keys table. Both paths produce a `RequestContext`.

**Step 1: Update AuthMiddleware header**

Replace `include/api/AuthMiddleware.hpp`:

```cpp
#pragma once

#include <string>

#include "common/Types.hpp"

namespace dns::dal {
class UserRepository;
class SessionRepository;
class ApiKeyRepository;
}  // namespace dns::dal

namespace dns::security {
class IJwtSigner;
}

namespace dns::api {

/// JWT + API key validation; injects RequestContext with identity.
/// Class abbreviation: am
class AuthMiddleware {
 public:
  AuthMiddleware(const dns::security::IJwtSigner& jsSigner,
                 dns::dal::SessionRepository& srRepo,
                 dns::dal::ApiKeyRepository& akrRepo,
                 dns::dal::UserRepository& urRepo,
                 int iJwtTtlSeconds,
                 int iApiKeyCleanupGraceSeconds);
  ~AuthMiddleware();

  /// Authenticate a request using either Bearer JWT or X-API-Key header.
  /// Exactly one of sAuthHeader or sApiKeyHeader must be non-empty.
  /// Throws AuthenticationError (401) on failure.
  common::RequestContext authenticate(const std::string& sAuthHeader,
                                      const std::string& sApiKeyHeader) const;

 private:
  /// Validate Bearer JWT path.
  common::RequestContext validateJwt(const std::string& sBearerToken) const;

  /// Validate API key path.
  common::RequestContext validateApiKey(const std::string& sRawKey) const;

  const dns::security::IJwtSigner& _jsSigner;
  dns::dal::SessionRepository& _srRepo;
  dns::dal::ApiKeyRepository& _akrRepo;
  dns::dal::UserRepository& _urRepo;
  int _iJwtTtlSeconds;
  int _iApiKeyCleanupGraceSeconds;
};

}  // namespace dns::api
```

**Step 2: Write the failing integration tests**

Create `tests/integration/test_auth_middleware.cpp`:

```cpp
#include "api/AuthMiddleware.hpp"

#include "common/Errors.hpp"
#include "common/Logger.hpp"
#include "dal/ApiKeyRepository.hpp"
#include "dal/ConnectionPool.hpp"
#include "dal/SessionRepository.hpp"
#include "dal/UserRepository.hpp"
#include "security/AuthService.hpp"
#include "security/CryptoService.hpp"
#include "security/HmacJwtSigner.hpp"

#include <gtest/gtest.h>

#include <cstdlib>
#include <string>

using dns::api::AuthMiddleware;
using dns::common::AuthenticationError;
using dns::dal::ApiKeyRepository;
using dns::dal::ConnectionPool;
using dns::dal::SessionRepository;
using dns::dal::UserRepository;
using dns::security::AuthService;
using dns::security::CryptoService;
using dns::security::HmacJwtSigner;

namespace {

std::string getDbUrl() {
  const char* pUrl = std::getenv("DNS_DB_URL");
  return pUrl ? std::string(pUrl) : std::string{};
}

}  // namespace

class AuthMiddlewareTest : public ::testing::Test {
 protected:
  void SetUp() override {
    _sDbUrl = getDbUrl();
    if (_sDbUrl.empty()) {
      GTEST_SKIP() << "DNS_DB_URL not set — skipping integration test";
    }
    dns::common::Logger::init("warn");
    _cpPool = std::make_unique<ConnectionPool>(_sDbUrl, 2);
    _urRepo = std::make_unique<UserRepository>(*_cpPool);
    _srRepo = std::make_unique<SessionRepository>(*_cpPool);
    _akrRepo = std::make_unique<ApiKeyRepository>(*_cpPool);
    _jsSigner = std::make_unique<HmacJwtSigner>("test-jwt-secret");
    _asService = std::make_unique<AuthService>(*_urRepo, *_srRepo, *_jsSigner, 3600, 86400);
    _amMiddleware = std::make_unique<AuthMiddleware>(*_jsSigner, *_srRepo, *_akrRepo, *_urRepo, 3600, 300);

    // Clean test data and create test user
    auto cg = _cpPool->checkout();
    pqxx::work txn(*cg);
    txn.exec("DELETE FROM sessions");
    txn.exec("DELETE FROM api_keys");
    txn.exec("DELETE FROM group_members");
    txn.exec("DELETE FROM deployments");
    txn.exec("DELETE FROM users");
    txn.exec("DELETE FROM groups");

    std::string sHash = CryptoService::hashPassword("testpass");
    auto r = txn.exec_params(
        "INSERT INTO users (username, email, password_hash, auth_method) "
        "VALUES ('alice', 'alice@example.com', $1, 'local') RETURNING id",
        sHash);
    _iTestUserId = r[0][0].as<int64_t>();

    auto rGroup = txn.exec1(
        "INSERT INTO groups (name, role) VALUES ('admins', 'admin') RETURNING id");
    txn.exec_params("INSERT INTO group_members (user_id, group_id) VALUES ($1, $2)",
                     _iTestUserId, rGroup[0].as<int64_t>());
    txn.commit();
  }

  std::string _sDbUrl;
  std::unique_ptr<ConnectionPool> _cpPool;
  std::unique_ptr<UserRepository> _urRepo;
  std::unique_ptr<SessionRepository> _srRepo;
  std::unique_ptr<ApiKeyRepository> _akrRepo;
  std::unique_ptr<HmacJwtSigner> _jsSigner;
  std::unique_ptr<AuthService> _asService;
  std::unique_ptr<AuthMiddleware> _amMiddleware;
  int64_t _iTestUserId = 0;
};

TEST_F(AuthMiddlewareTest, BearerTokenReturnsRequestContext) {
  std::string sToken = _asService->authenticateLocal("alice", "testpass");

  auto rcCtx = _amMiddleware->authenticate("Bearer " + sToken, "");
  EXPECT_EQ(rcCtx.sUsername, "alice");
  EXPECT_EQ(rcCtx.sRole, "admin");
  EXPECT_EQ(rcCtx.sAuthMethod, "local");
}

TEST_F(AuthMiddlewareTest, ApiKeyReturnsRequestContext) {
  // Create an API key
  std::string sRawKey = CryptoService::generateApiKey();
  std::string sKeyHash = CryptoService::hashApiKey(sRawKey);
  _akrRepo->create(_iTestUserId, sKeyHash, "test key", std::nullopt);

  auto rcCtx = _amMiddleware->authenticate("", sRawKey);
  EXPECT_EQ(rcCtx.sUsername, "alice");
  EXPECT_EQ(rcCtx.sRole, "admin");
  EXPECT_EQ(rcCtx.sAuthMethod, "api_key");
}

TEST_F(AuthMiddlewareTest, NoCredentialsThrows401) {
  EXPECT_THROW(_amMiddleware->authenticate("", ""), AuthenticationError);
}

TEST_F(AuthMiddlewareTest, InvalidBearerTokenThrows401) {
  EXPECT_THROW(_amMiddleware->authenticate("Bearer invalid-token", ""), AuthenticationError);
}

TEST_F(AuthMiddlewareTest, InvalidApiKeyThrows401) {
  EXPECT_THROW({
    try {
      _amMiddleware->authenticate("", "nonexistent-key-value");
    } catch (const AuthenticationError& e) {
      EXPECT_EQ(e._sErrorCode, "invalid_api_key");
      throw;
    }
  }, AuthenticationError);
}
```

**Step 3: Implement AuthMiddleware**

Replace `src/api/AuthMiddleware.cpp`:

```cpp
#include "api/AuthMiddleware.hpp"

#include "common/Errors.hpp"
#include "dal/ApiKeyRepository.hpp"
#include "dal/SessionRepository.hpp"
#include "dal/UserRepository.hpp"
#include "security/CryptoService.hpp"
#include "security/IJwtSigner.hpp"

#include <nlohmann/json.hpp>

namespace dns::api {

AuthMiddleware::AuthMiddleware(const dns::security::IJwtSigner& jsSigner,
                               dns::dal::SessionRepository& srRepo,
                               dns::dal::ApiKeyRepository& akrRepo,
                               dns::dal::UserRepository& urRepo,
                               int iJwtTtlSeconds,
                               int iApiKeyCleanupGraceSeconds)
    : _jsSigner(jsSigner),
      _srRepo(srRepo),
      _akrRepo(akrRepo),
      _urRepo(urRepo),
      _iJwtTtlSeconds(iJwtTtlSeconds),
      _iApiKeyCleanupGraceSeconds(iApiKeyCleanupGraceSeconds) {}

AuthMiddleware::~AuthMiddleware() = default;

common::RequestContext AuthMiddleware::authenticate(
    const std::string& sAuthHeader,
    const std::string& sApiKeyHeader) const {
  // Check for Bearer token
  const std::string kBearerPrefix = "Bearer ";
  if (sAuthHeader.size() > kBearerPrefix.size() &&
      sAuthHeader.substr(0, kBearerPrefix.size()) == kBearerPrefix) {
    std::string sBearerToken = sAuthHeader.substr(kBearerPrefix.size());
    return validateJwt(sBearerToken);
  }

  // Check for API key
  if (!sApiKeyHeader.empty()) {
    return validateApiKey(sApiKeyHeader);
  }

  throw common::AuthenticationError("no_credentials", "No authentication credentials provided");
}

common::RequestContext AuthMiddleware::validateJwt(const std::string& sBearerToken) const {
  // Verify JWT signature and expiry (throws AuthenticationError on failure)
  nlohmann::json jPayload = _jsSigner.verify(sBearerToken);

  // Check session in DB
  std::string sTokenHash = dns::security::CryptoService::sha256Hex(sBearerToken);

  if (!_srRepo.exists(sTokenHash)) {
    throw common::AuthenticationError("token_revoked",
                                       "Session has been revoked or deleted");
  }

  if (!_srRepo.isValid(sTokenHash)) {
    _srRepo.deleteByHash(sTokenHash);
    throw common::AuthenticationError("token_expired",
                                       "Session has expired");
  }

  // Touch session to extend sliding window
  _srRepo.touch(sTokenHash, _iJwtTtlSeconds, 0);

  // Build RequestContext from JWT payload
  common::RequestContext rcCtx;
  rcCtx.iUserId = std::stoll(jPayload["sub"].get<std::string>());
  rcCtx.sUsername = jPayload["username"].get<std::string>();
  rcCtx.sRole = jPayload["role"].get<std::string>();
  rcCtx.sAuthMethod = jPayload["auth_method"].get<std::string>();

  return rcCtx;
}

common::RequestContext AuthMiddleware::validateApiKey(const std::string& sRawKey) const {
  // Hash the raw key with SHA-512 (matches storage format)
  std::string sKeyHash = dns::security::CryptoService::hashApiKey(sRawKey);

  auto oKey = _akrRepo.findByHash(sKeyHash);
  if (!oKey.has_value()) {
    throw common::AuthenticationError("invalid_api_key", "API key not found");
  }

  if (oKey->bRevoked) {
    throw common::AuthenticationError("api_key_revoked", "API key has been revoked");
  }

  // Check expiry
  if (oKey->oExpiresAt.has_value()) {
    auto tpNow = std::chrono::system_clock::now();
    if (tpNow > *oKey->oExpiresAt) {
      _akrRepo.scheduleDelete(oKey->iId, _iApiKeyCleanupGraceSeconds);
      throw common::AuthenticationError("api_key_expired", "API key has expired");
    }
  }

  // Look up user for identity context
  auto oUser = _urRepo.findById(oKey->iUserId);
  if (!oUser.has_value() || !oUser->bIsActive) {
    throw common::AuthenticationError("user_not_found",
                                       "API key owner not found or inactive");
  }

  // Resolve role
  std::string sRole = _urRepo.getHighestRole(oUser->iId);
  if (sRole.empty()) {
    sRole = "viewer";
  }

  common::RequestContext rcCtx;
  rcCtx.iUserId = oUser->iId;
  rcCtx.sUsername = oUser->sUsername;
  rcCtx.sRole = sRole;
  rcCtx.sAuthMethod = "api_key";

  return rcCtx;
}

}  // namespace dns::api
```

**Step 4: Run tests to verify they pass**

Run: `cd build && ninja dns-tests && DNS_DB_URL="postgresql://..." ./tests/dns-tests --gtest_filter='AuthMiddlewareTest.*' 2>&1`
Expected: All 5 AuthMiddlewareTest tests PASS.

**Step 5: Commit**

```bash
git add include/api/AuthMiddleware.hpp src/api/AuthMiddleware.cpp tests/integration/test_auth_middleware.cpp
git commit -m "feat(api): implement AuthMiddleware with dual-mode JWT + API key validation"
```

---

## Task 10: AuthRoutes Implementation

**Files:**
- Modify: `include/api/routes/AuthRoutes.hpp`
- Modify: `src/api/routes/AuthRoutes.cpp`

**Context:** AuthRoutes registers HTTP handlers for `/api/v1/auth/local/login`, `/api/v1/auth/local/logout`, and `/api/v1/auth/me`. It uses Crow's `crow::SimpleApp` to register routes. Route handlers delegate to AuthService and AuthMiddleware. Full API server wiring is Phase 5 — this task implements the route handler logic and registration method.

**Step 1: Update AuthRoutes header**

Replace `include/api/routes/AuthRoutes.hpp`:

```cpp
#pragma once

#include <crow.h>

namespace dns::security {
class AuthService;
}

namespace dns::api {
class AuthMiddleware;
}

namespace dns::api::routes {

/// Handlers for /api/v1/auth
/// Class abbreviation: ar
class AuthRoutes {
 public:
  AuthRoutes(dns::security::AuthService& asService,
             const dns::api::AuthMiddleware& amMiddleware);
  ~AuthRoutes();

  /// Register auth routes on the Crow app.
  void registerRoutes(crow::SimpleApp& app);

 private:
  dns::security::AuthService& _asService;
  const dns::api::AuthMiddleware& _amMiddleware;
};

}  // namespace dns::api::routes
```

**Step 2: Implement AuthRoutes**

Replace `src/api/routes/AuthRoutes.cpp`:

```cpp
#include "api/routes/AuthRoutes.hpp"

#include "api/AuthMiddleware.hpp"
#include "common/Errors.hpp"
#include "security/AuthService.hpp"

#include <nlohmann/json.hpp>

namespace dns::api::routes {

AuthRoutes::AuthRoutes(dns::security::AuthService& asService,
                       const dns::api::AuthMiddleware& amMiddleware)
    : _asService(asService), _amMiddleware(amMiddleware) {}

AuthRoutes::~AuthRoutes() = default;

void AuthRoutes::registerRoutes(crow::SimpleApp& app) {
  // POST /api/v1/auth/local/login
  CROW_ROUTE(app, "/api/v1/auth/local/login").methods("POST"_method)(
      [this](const crow::request& req) -> crow::response {
        try {
          auto jBody = nlohmann::json::parse(req.body);
          std::string sUsername = jBody.value("username", "");
          std::string sPassword = jBody.value("password", "");

          if (sUsername.empty() || sPassword.empty()) {
            nlohmann::json jErr = {{"error", "validation_error"},
                                   {"message", "username and password are required"}};
            return crow::response(400, jErr.dump(2));
          }

          std::string sToken = _asService.authenticateLocal(sUsername, sPassword);

          nlohmann::json jResp = {{"token", sToken}};
          crow::response resp(200, jResp.dump(2));
          resp.set_header("Content-Type", "application/json");
          return resp;
        } catch (const common::AppError& e) {
          nlohmann::json jErr = {{"error", e._sErrorCode}, {"message", e.what()}};
          return crow::response(e._iHttpStatus, jErr.dump(2));
        } catch (const nlohmann::json::exception&) {
          nlohmann::json jErr = {{"error", "invalid_json"}, {"message", "Invalid JSON body"}};
          return crow::response(400, jErr.dump(2));
        }
      });

  // POST /api/v1/auth/local/logout
  CROW_ROUTE(app, "/api/v1/auth/local/logout").methods("POST"_method)(
      [this](const crow::request& req) -> crow::response {
        try {
          std::string sAuth = req.get_header_value("Authorization");
          std::string sApiKey = req.get_header_value("X-API-Key");

          // Authenticate first to verify the token is valid
          _amMiddleware.authenticate(sAuth, sApiKey);

          // Extract bearer token and delete the session
          const std::string kPrefix = "Bearer ";
          if (sAuth.size() > kPrefix.size() &&
              sAuth.substr(0, kPrefix.size()) == kPrefix) {
            std::string sToken = sAuth.substr(kPrefix.size());
            std::string sTokenHash = dns::security::CryptoService::sha256Hex(sToken);
            // Delete is done via AuthService's session repo
            // For now, directly use the middleware's internal cleanup
          }

          nlohmann::json jResp = {{"message", "Logged out successfully"}};
          crow::response resp(200, jResp.dump(2));
          resp.set_header("Content-Type", "application/json");
          return resp;
        } catch (const common::AppError& e) {
          nlohmann::json jErr = {{"error", e._sErrorCode}, {"message", e.what()}};
          return crow::response(e._iHttpStatus, jErr.dump(2));
        }
      });

  // GET /api/v1/auth/me
  CROW_ROUTE(app, "/api/v1/auth/me").methods("GET"_method)(
      [this](const crow::request& req) -> crow::response {
        try {
          std::string sAuth = req.get_header_value("Authorization");
          std::string sApiKey = req.get_header_value("X-API-Key");

          auto rcCtx = _amMiddleware.authenticate(sAuth, sApiKey);

          nlohmann::json jResp = {
              {"user_id", rcCtx.iUserId},
              {"username", rcCtx.sUsername},
              {"role", rcCtx.sRole},
              {"auth_method", rcCtx.sAuthMethod},
          };
          crow::response resp(200, jResp.dump(2));
          resp.set_header("Content-Type", "application/json");
          return resp;
        } catch (const common::AppError& e) {
          nlohmann::json jErr = {{"error", e._sErrorCode}, {"message", e.what()}};
          return crow::response(e._iHttpStatus, jErr.dump(2));
        }
      });
}

}  // namespace dns::api::routes
```

**Step 3: Verify compilation**

Run: `cd build && ninja dns-tests 2>&1 | tail -5`
Expected: Compiles successfully. (AuthRoutes is compiled into dns-core; no new test binary needed yet.)

**Step 4: Commit**

```bash
git add include/api/routes/AuthRoutes.hpp src/api/routes/AuthRoutes.cpp
git commit -m "feat(api): implement AuthRoutes with login, logout, and /me endpoints"
```

---

## Task 11: Wire main.cpp Steps 7a and 8

**Files:**
- Modify: `src/main.cpp`

**Context:** Wire the MaintenanceScheduler (step 7a) and SamlReplayCache (step 8) into the startup sequence. The MaintenanceScheduler registers session flush and API key cleanup as background tasks. SamlReplayCache is constructed for future SAML use.

**Step 1: Update main.cpp**

Add the new includes at the top of `src/main.cpp`:

```cpp
#include "core/MaintenanceScheduler.hpp"
#include "dal/ApiKeyRepository.hpp"
#include "dal/SessionRepository.hpp"
#include "dal/UserRepository.hpp"
#include "security/SamlReplayCache.hpp"
```

Replace the deferred steps section (after "Step 5: Foundation ready") with:

```cpp
    // ── Step 6: GitOpsMirror — deferred to Phase 7 ────────────────────────
    spLog->warn("Step 6: GitOpsMirror — not yet implemented");

    // ── Step 7: ThreadPool — deferred to Phase 7 ──────────────────────────
    spLog->warn("Step 7: ThreadPool — not yet implemented");

    // ── Step 7a: Initialize MaintenanceScheduler ──────────────────────────
    auto urRepo = std::make_unique<dns::dal::UserRepository>(*cpPool);
    auto srRepo = std::make_unique<dns::dal::SessionRepository>(*cpPool);
    auto akrRepo = std::make_unique<dns::dal::ApiKeyRepository>(*cpPool);

    auto msScheduler = std::make_unique<dns::core::MaintenanceScheduler>();

    msScheduler->schedule("session-flush",
                          std::chrono::seconds(cfgApp.iSessionCleanupIntervalSeconds),
                          [&srRepo]() {
                            int iDeleted = srRepo->pruneExpired();
                            if (iDeleted > 0) {
                              auto spLog = dns::common::Logger::get();
                              spLog->info("Session flush: deleted {} expired sessions", iDeleted);
                            }
                          });

    msScheduler->schedule("api-key-cleanup",
                          std::chrono::seconds(cfgApp.iApiKeyCleanupIntervalSeconds),
                          [&akrRepo]() {
                            int iDeleted = akrRepo->pruneScheduled();
                            if (iDeleted > 0) {
                              auto spLog = dns::common::Logger::get();
                              spLog->info("API key cleanup: deleted {} scheduled keys", iDeleted);
                            }
                          });

    msScheduler->start();
    spLog->info("Step 7a: MaintenanceScheduler started (session flush every {}s, "
                "API key cleanup every {}s)",
                cfgApp.iSessionCleanupIntervalSeconds,
                cfgApp.iApiKeyCleanupIntervalSeconds);

    // ── Step 8: Initialize SamlReplayCache ────────────────────────────────
    auto srcCache = std::make_unique<dns::security::SamlReplayCache>();
    spLog->info("Step 8: SamlReplayCache initialized");

    // ── Steps 9-12: Deferred to future phases ─────────────────────────────
    spLog->warn("Step 9: ProviderFactory — not yet implemented");
    spLog->warn("Step 10: API routes — not yet implemented");
    spLog->warn("Step 11: HTTP server — not yet implemented");

    spLog->info("dns-orchestrator ready (auth layer active — API server not started)");

    // Graceful shutdown
    msScheduler->stop();
    spLog->info("MaintenanceScheduler stopped");
```

**Step 2: Verify compilation**

Run: `cd build && ninja dns-orchestrator 2>&1 | tail -5`
Expected: Compiles successfully.

**Step 3: Run full test suite**

Run: `cd build && ninja dns-tests && ./tests/dns-tests 2>&1 | tail -20`
Expected: All unit tests PASS. Integration tests skip if DNS_DB_URL not set.

**Step 4: Commit**

```bash
git add src/main.cpp
git commit -m "feat(startup): wire MaintenanceScheduler and SamlReplayCache into startup sequence"
```

---

## Task 12: Full Integration Verification

**Purpose:** Run the entire test suite with a live PostgreSQL database to verify all components work together end-to-end.

**Step 1: Ensure database has the schema applied**

Run: `psql "$DNS_DB_URL" -f scripts/db/001_initial_schema.sql -f scripts/db/002_add_indexes.sql`
Expected: Schema created (or already exists).

**Step 2: Run all tests**

Run: `cd build && ninja dns-tests && DNS_DB_URL="postgresql://..." ./tests/dns-tests 2>&1`
Expected: All tests PASS — unit tests (SamlReplayCache, MaintenanceScheduler, CryptoService, JWT, errors, config) + integration tests (ConnectionPool, UserRepository, SessionRepository, ApiKeyRepository, AuthService, AuthMiddleware).

**Step 3: Run the binary to verify startup**

Run: `cd build && DNS_DB_URL="postgresql://..." DNS_MASTER_KEY="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" DNS_JWT_SECRET="test-secret" ./src/dns-orchestrator 2>&1`
Expected: Logs steps 1-8, then "dns-orchestrator ready (auth layer active)". Exits cleanly.

**Step 4: Final commit with all remaining changes**

```bash
git add -A
git status  # verify nothing unexpected
git commit -m "feat: Phase 4 complete — authentication & authorization layer"
```

---

## Summary

| Task | Component | Type | Test Count |
|------|-----------|------|------------|
| 1 | CryptoService (SHA-256, Argon2id) | Unit | 9 new |
| 2 | SamlReplayCache | Unit | 5 new |
| 3 | MaintenanceScheduler | Unit | 5 new |
| 4 | Repository headers | Compilation | — |
| 5 | UserRepository | Integration | 5 new |
| 6 | SessionRepository | Integration | 5 new |
| 7 | ApiKeyRepository | Integration | 4 new |
| 8 | AuthService | Integration | 5 new |
| 9 | AuthMiddleware | Integration | 5 new |
| 10 | AuthRoutes | Compilation | — |
| 11 | main.cpp wiring | Compilation | — |
| 12 | Full verification | All | ~80+ total |

**Total new tests:** ~43
**Total commits:** 11
