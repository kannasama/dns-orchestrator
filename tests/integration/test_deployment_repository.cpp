#include "dal/DeploymentRepository.hpp"

#include "common/Logger.hpp"
#include "dal/ConnectionPool.hpp"
#include "dal/ViewRepository.hpp"
#include "dal/ZoneRepository.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <cstdlib>
#include <string>

using dns::dal::ConnectionPool;
using dns::dal::DeploymentRepository;
using dns::dal::DeploymentRow;
using dns::dal::ViewRepository;
using dns::dal::ZoneRepository;

namespace {

std::string getDbUrl() {
  const char* pUrl = std::getenv("DNS_DB_URL");
  return pUrl ? std::string(pUrl) : std::string{};
}

}  // namespace

class DeploymentRepositoryTest : public ::testing::Test {
 protected:
  void SetUp() override {
    _sDbUrl = getDbUrl();
    if (_sDbUrl.empty()) {
      GTEST_SKIP() << "DNS_DB_URL not set — skipping integration test";
    }
    dns::common::Logger::init("warn");
    _cpPool = std::make_unique<ConnectionPool>(_sDbUrl, 2);
    _vrRepo = std::make_unique<ViewRepository>(*_cpPool);
    _zrRepo = std::make_unique<ZoneRepository>(*_cpPool);
    _drRepo = std::make_unique<DeploymentRepository>(*_cpPool);

    auto cg = _cpPool->checkout();
    pqxx::work txn(*cg);
    txn.exec("DELETE FROM records");
    txn.exec("DELETE FROM variables");
    txn.exec("DELETE FROM deployments");
    txn.exec("DELETE FROM zones");
    txn.exec("DELETE FROM view_providers");
    txn.exec("DELETE FROM views");
    txn.commit();

    _iViewId = _vrRepo->create("dep-view", "For deployment tests");
    _iZoneId = _zrRepo->create("deploy.com", _iViewId, std::nullopt);

    // Create a test user for deployed_by FK
    auto cg2 = _cpPool->checkout();
    pqxx::work txn2(*cg2);
    txn2.exec("DELETE FROM group_members");
    txn2.exec("DELETE FROM sessions");
    txn2.exec("DELETE FROM api_keys");
    txn2.exec("DELETE FROM users");
    auto uResult = txn2.exec(
        "INSERT INTO users (username, email, password_hash, auth_method) "
        "VALUES ('deployer', 'dep@test.com', 'hash', 'local') RETURNING id");
    _iUserId = uResult.one_row()[0].as<int64_t>();
    txn2.commit();
  }

  std::string _sDbUrl;
  std::unique_ptr<ConnectionPool> _cpPool;
  std::unique_ptr<ViewRepository> _vrRepo;
  std::unique_ptr<ZoneRepository> _zrRepo;
  std::unique_ptr<DeploymentRepository> _drRepo;
  int64_t _iViewId = 0;
  int64_t _iZoneId = 0;
  int64_t _iUserId = 0;
};

TEST_F(DeploymentRepositoryTest, CreateAndFindById) {
  nlohmann::json jSnap = {{"records", {{{"name", "www"}, {"type", "A"}, {"value", "1.2.3.4"}}}}};
  int64_t iId = _drRepo->create(_iZoneId, _iUserId, jSnap);
  EXPECT_GT(iId, 0);

  auto oRow = _drRepo->findById(iId);
  ASSERT_TRUE(oRow.has_value());
  EXPECT_EQ(oRow->iZoneId, _iZoneId);
  EXPECT_EQ(oRow->iDeployedByUserId, _iUserId);
  EXPECT_EQ(oRow->iSeq, 1);
  EXPECT_EQ(oRow->jSnapshot["records"][0]["name"], "www");
}

TEST_F(DeploymentRepositoryTest, SeqAutoIncrements) {
  nlohmann::json jSnap = {{"v", 1}};
  _drRepo->create(_iZoneId, _iUserId, jSnap);
  _drRepo->create(_iZoneId, _iUserId, jSnap);
  int64_t iId3 = _drRepo->create(_iZoneId, _iUserId, jSnap);

  auto oRow = _drRepo->findById(iId3);
  ASSERT_TRUE(oRow.has_value());
  EXPECT_EQ(oRow->iSeq, 3);
}

TEST_F(DeploymentRepositoryTest, ListByZoneIdOrdered) {
  nlohmann::json jSnap = {{"v", 1}};
  _drRepo->create(_iZoneId, _iUserId, jSnap);
  _drRepo->create(_iZoneId, _iUserId, jSnap);
  _drRepo->create(_iZoneId, _iUserId, jSnap);

  auto vRows = _drRepo->listByZoneId(_iZoneId);
  ASSERT_EQ(vRows.size(), 3u);
  EXPECT_EQ(vRows[0].iSeq, 3);  // DESC order
  EXPECT_EQ(vRows[2].iSeq, 1);
}

TEST_F(DeploymentRepositoryTest, PruneByRetention) {
  nlohmann::json jSnap = {{"v", 1}};
  for (int i = 0; i < 5; ++i) {
    _drRepo->create(_iZoneId, _iUserId, jSnap);
  }

  int iDeleted = _drRepo->pruneByRetention(_iZoneId, 3);
  EXPECT_EQ(iDeleted, 2);

  auto vRows = _drRepo->listByZoneId(_iZoneId);
  EXPECT_EQ(vRows.size(), 3u);
}
