#include "dal/AuditRepository.hpp"

#include "common/Logger.hpp"
#include "dal/ConnectionPool.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <cstdlib>
#include <string>

using dns::dal::AuditRepository;
using dns::dal::AuditLogRow;
using dns::dal::ConnectionPool;
using dns::dal::PurgeResult;

namespace {

std::string getDbUrl() {
  const char* pUrl = std::getenv("DNS_DB_URL");
  return pUrl ? std::string(pUrl) : std::string{};
}

}  // namespace

class AuditRepositoryTest : public ::testing::Test {
 protected:
  void SetUp() override {
    _sDbUrl = getDbUrl();
    if (_sDbUrl.empty()) {
      GTEST_SKIP() << "DNS_DB_URL not set — skipping integration test";
    }
    dns::common::Logger::init("warn");
    _cpPool = std::make_unique<ConnectionPool>(_sDbUrl, 2);
    _arRepo = std::make_unique<AuditRepository>(*_cpPool);

    auto cg = _cpPool->checkout();
    pqxx::work txn(*cg);
    txn.exec("DELETE FROM audit_log");
    txn.commit();
  }

  std::string _sDbUrl;
  std::unique_ptr<ConnectionPool> _cpPool;
  std::unique_ptr<AuditRepository> _arRepo;
};

TEST_F(AuditRepositoryTest, InsertAndQuery) {
  nlohmann::json jNew = {{"name", "test-provider"}};
  int64_t iId = _arRepo->insert("provider", 42, "create",
                                std::nullopt, jNew,
                                "alice", "local", "127.0.0.1");
  EXPECT_GT(iId, 0);

  auto vRows = _arRepo->query("provider", std::nullopt, std::nullopt,
                              std::nullopt, std::nullopt);
  ASSERT_GE(vRows.size(), 1u);
  EXPECT_EQ(vRows[0].sEntityType, "provider");
  EXPECT_EQ(vRows[0].sOperation, "create");
  EXPECT_EQ(vRows[0].sIdentity, "alice");
}

TEST_F(AuditRepositoryTest, QueryFilters) {
  _arRepo->insert("provider", 1, "create", std::nullopt, std::nullopt,
                  "alice", "local", std::nullopt);
  _arRepo->insert("zone", 2, "update", std::nullopt, std::nullopt,
                  "bob", "local", std::nullopt);
  _arRepo->insert("provider", 3, "delete", std::nullopt, std::nullopt,
                  "alice", "local", std::nullopt);

  auto vAlice = _arRepo->query(std::nullopt, std::nullopt, "alice",
                               std::nullopt, std::nullopt);
  EXPECT_EQ(vAlice.size(), 2u);

  auto vProviders = _arRepo->query("provider", std::nullopt, std::nullopt,
                                   std::nullopt, std::nullopt);
  EXPECT_EQ(vProviders.size(), 2u);
}

TEST_F(AuditRepositoryTest, PurgeOld) {
  // Insert an old entry via raw SQL
  auto cg = _cpPool->checkout();
  pqxx::work txn(*cg);
  txn.exec(
      "INSERT INTO audit_log (entity_type, operation, identity, timestamp) "
      "VALUES ('test', 'old', 'system', NOW() - interval '400 days')");
  txn.commit();

  // Insert a recent entry
  _arRepo->insert("test", std::nullopt, "recent", std::nullopt, std::nullopt,
                  "system", std::nullopt, std::nullopt);

  auto pr = _arRepo->purgeOld(365);
  EXPECT_EQ(pr.iDeletedCount, 1);
  EXPECT_TRUE(pr.oOldestRemaining.has_value());
}
