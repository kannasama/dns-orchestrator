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
    auto r = txn.exec(
        "INSERT INTO users (username, email, password_hash, auth_method) "
        "VALUES ('testuser', 'test@example.com', 'hash', 'local') RETURNING id");
    _iTestUserId = r.one_row()[0].as<int64_t>();
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
  txn.exec(
      "INSERT INTO sessions (user_id, token_hash, expires_at, absolute_expires_at) "
      "VALUES ($1, 'expired-token', NOW() - INTERVAL '1 hour', NOW() - INTERVAL '1 hour')",
      pqxx::params{_iTestUserId});
  txn.commit();

  EXPECT_TRUE(_srRepo->exists("expired-token"));

  int iDeleted = _srRepo->pruneExpired();
  EXPECT_GE(iDeleted, 1);
  EXPECT_FALSE(_srRepo->exists("expired-token"));
}
