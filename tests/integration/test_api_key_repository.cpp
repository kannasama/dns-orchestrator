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
    auto r = txn.exec(
        "INSERT INTO users (username, email, password_hash, auth_method) "
        "VALUES ('apiuser', 'api@example.com', 'hash', 'local') RETURNING id");
    _iTestUserId = r.one_row()[0].as<int64_t>();
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
