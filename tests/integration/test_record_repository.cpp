#include "dal/RecordRepository.hpp"

#include "common/Errors.hpp"
#include "common/Logger.hpp"
#include "dal/ConnectionPool.hpp"
#include "dal/ViewRepository.hpp"
#include "dal/ZoneRepository.hpp"

#include <gtest/gtest.h>

#include <cstdlib>
#include <string>

using dns::dal::ConnectionPool;
using dns::dal::RecordRepository;
using dns::dal::RecordRow;
using dns::dal::ViewRepository;
using dns::dal::ZoneRepository;

namespace {

std::string getDbUrl() {
  const char* pUrl = std::getenv("DNS_DB_URL");
  return pUrl ? std::string(pUrl) : std::string{};
}

}  // namespace

class RecordRepositoryTest : public ::testing::Test {
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
    _rrRepo = std::make_unique<RecordRepository>(*_cpPool);

    auto cg = _cpPool->checkout();
    pqxx::work txn(*cg);
    txn.exec("DELETE FROM records");
    txn.exec("DELETE FROM variables");
    txn.exec("DELETE FROM deployments");
    txn.exec("DELETE FROM zones");
    txn.exec("DELETE FROM view_providers");
    txn.exec("DELETE FROM views");
    txn.commit();

    _iViewId = _vrRepo->create("rec-view", "For record tests");
    _iZoneId = _zrRepo->create("example.com", _iViewId, std::nullopt);
  }

  std::string _sDbUrl;
  std::unique_ptr<ConnectionPool> _cpPool;
  std::unique_ptr<ViewRepository> _vrRepo;
  std::unique_ptr<ZoneRepository> _zrRepo;
  std::unique_ptr<RecordRepository> _rrRepo;
  int64_t _iViewId = 0;
  int64_t _iZoneId = 0;
};

TEST_F(RecordRepositoryTest, CreateAndFindById) {
  int64_t iId = _rrRepo->create(_iZoneId, "www", "A", 300, "{{LB_VIP}}", 0);
  EXPECT_GT(iId, 0);

  auto oRow = _rrRepo->findById(iId);
  ASSERT_TRUE(oRow.has_value());
  EXPECT_EQ(oRow->sName, "www");
  EXPECT_EQ(oRow->sType, "A");
  EXPECT_EQ(oRow->iTtl, 300);
  EXPECT_EQ(oRow->sValueTemplate, "{{LB_VIP}}");
  EXPECT_EQ(oRow->iPriority, 0);
}

TEST_F(RecordRepositoryTest, ListByZoneId) {
  int64_t iZone2 = _zrRepo->create("other.com", _iViewId, std::nullopt);
  _rrRepo->create(_iZoneId, "www", "A", 300, "1.2.3.4", 0);
  _rrRepo->create(_iZoneId, "mail", "MX", 300, "mail.example.com", 10);
  _rrRepo->create(iZone2, "ns1", "NS", 300, "ns1.other.com", 0);

  auto vRows = _rrRepo->listByZoneId(_iZoneId);
  EXPECT_EQ(vRows.size(), 2u);
}

TEST_F(RecordRepositoryTest, Update) {
  int64_t iId = _rrRepo->create(_iZoneId, "www", "A", 300, "1.2.3.4", 0);

  _rrRepo->update(iId, "www", "A", 600, "5.6.7.8", 0);

  auto oRow = _rrRepo->findById(iId);
  ASSERT_TRUE(oRow.has_value());
  EXPECT_EQ(oRow->iTtl, 600);
  EXPECT_EQ(oRow->sValueTemplate, "5.6.7.8");
}

TEST_F(RecordRepositoryTest, DeleteById) {
  int64_t iId = _rrRepo->create(_iZoneId, "del", "A", 300, "1.1.1.1", 0);
  _rrRepo->deleteById(iId);

  auto oRow = _rrRepo->findById(iId);
  EXPECT_FALSE(oRow.has_value());
}

TEST_F(RecordRepositoryTest, InvalidZoneIdThrows) {
  EXPECT_THROW(_rrRepo->create(999999, "bad", "A", 300, "1.1.1.1", 0),
               dns::common::ValidationError);
}
