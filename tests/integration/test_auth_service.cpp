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
    auto r = txn.exec(
        "INSERT INTO users (username, email, password_hash, auth_method) "
        "VALUES ('alice', 'alice@example.com', $1, 'local') RETURNING id",
        pqxx::params{sHash});
    _iTestUserId = r.one_row()[0].as<int64_t>();

    // Create group and membership for role resolution
    auto rGroup = txn.exec(
        "INSERT INTO groups (name, role) VALUES ('operators', 'operator') RETURNING id").one_row();
    txn.exec("INSERT INTO group_members (user_id, group_id) VALUES ($1, $2)",
             pqxx::params{_iTestUserId, rGroup[0].as<int64_t>()});
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
