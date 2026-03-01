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
    auto r = txn.exec(
        "INSERT INTO users (username, email, password_hash, auth_method) "
        "VALUES ('alice', 'alice@example.com', $1, 'local') RETURNING id",
        pqxx::params{sHash});
    _iTestUserId = r.one_row()[0].as<int64_t>();

    auto rGroup = txn.exec(
        "INSERT INTO groups (name, role) VALUES ('admins', 'admin') RETURNING id").one_row();
    txn.exec("INSERT INTO group_members (user_id, group_id) VALUES ($1, $2)",
             pqxx::params{_iTestUserId, rGroup[0].as<int64_t>()});
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
