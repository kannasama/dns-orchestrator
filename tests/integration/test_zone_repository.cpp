#include "dal/ZoneRepository.hpp"

#include "common/Errors.hpp"
#include "common/Logger.hpp"
#include "dal/ConnectionPool.hpp"
#include "dal/ViewRepository.hpp"

#include <gtest/gtest.h>

#include <cstdlib>
#include <string>

using dns::dal::ConnectionPool;
using dns::dal::ViewRepository;
using dns::dal::ZoneRepository;
using dns::dal::ZoneRow;

namespace {

std::string getDbUrl() {
  const char* pUrl = std::getenv("DNS_DB_URL");
  return pUrl ? std::string(pUrl) : std::string{};
}

}  // namespace

class ZoneRepositoryTest : public ::testing::Test {
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

    // Clean test data
    auto cg = _cpPool->checkout();
    pqxx::work txn(*cg);
    txn.exec("DELETE FROM records");
    txn.exec("DELETE FROM variables");
    txn.exec("DELETE FROM deployments");
    txn.exec("DELETE FROM zones");
    txn.exec("DELETE FROM view_providers");
    txn.exec("DELETE FROM views");
    txn.commit();

    // Create a test view
    _iViewId = _vrRepo->create("test-view", "For zone tests");
  }

  std::string _sDbUrl;
  std::unique_ptr<ConnectionPool> _cpPool;
  std::unique_ptr<ViewRepository> _vrRepo;
  std::unique_ptr<ZoneRepository> _zrRepo;
  int64_t _iViewId = 0;
};

TEST_F(ZoneRepositoryTest, CreateAndFindById) {
  int64_t iId = _zrRepo->create("example.com", _iViewId, 5);
  EXPECT_GT(iId, 0);

  auto oRow = _zrRepo->findById(iId);
  ASSERT_TRUE(oRow.has_value());
  EXPECT_EQ(oRow->sName, "example.com");
  EXPECT_EQ(oRow->iViewId, _iViewId);
  ASSERT_TRUE(oRow->oDeploymentRetention.has_value());
  EXPECT_EQ(*oRow->oDeploymentRetention, 5);
}

TEST_F(ZoneRepositoryTest, ListByViewId) {
  int64_t iView2 = _vrRepo->create("view-2", "Second view");
  _zrRepo->create("a.com", _iViewId, std::nullopt);
  _zrRepo->create("b.com", _iViewId, std::nullopt);
  _zrRepo->create("c.com", iView2, std::nullopt);

  auto vRows = _zrRepo->listByViewId(_iViewId);
  EXPECT_EQ(vRows.size(), 2u);
}

TEST_F(ZoneRepositoryTest, DuplicateNameSameViewThrows) {
  _zrRepo->create("dup.com", _iViewId, std::nullopt);
  EXPECT_THROW(_zrRepo->create("dup.com", _iViewId, std::nullopt),
               dns::common::ConflictError);
}

TEST_F(ZoneRepositoryTest, SameNameDifferentViewAllowed) {
  int64_t iView2 = _vrRepo->create("view-diff", "Different view");
  _zrRepo->create("shared.com", _iViewId, std::nullopt);
  EXPECT_NO_THROW(_zrRepo->create("shared.com", iView2, std::nullopt));
}

TEST_F(ZoneRepositoryTest, DeleteCascades) {
  int64_t iZoneId = _zrRepo->create("cascade.com", _iViewId, std::nullopt);

  // Add a record to verify cascade
  auto cg = _cpPool->checkout();
  pqxx::work txn(*cg);
  txn.exec("INSERT INTO records (zone_id, name, type, value_template) "
           "VALUES ($1, 'www', 'A', '1.2.3.4')",
           pqxx::params{iZoneId});
  txn.commit();

  _zrRepo->deleteById(iZoneId);

  auto oRow = _zrRepo->findById(iZoneId);
  EXPECT_FALSE(oRow.has_value());
}

TEST_F(ZoneRepositoryTest, InvalidViewIdThrows) {
  EXPECT_THROW(_zrRepo->create("bad.com", 999999, std::nullopt),
               dns::common::ValidationError);
}
