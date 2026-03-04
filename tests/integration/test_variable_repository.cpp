#include "dal/VariableRepository.hpp"

#include "common/Errors.hpp"
#include "common/Logger.hpp"
#include "dal/ConnectionPool.hpp"
#include "dal/ViewRepository.hpp"
#include "dal/ZoneRepository.hpp"

#include <gtest/gtest.h>

#include <cstdlib>
#include <string>

using dns::dal::ConnectionPool;
using dns::dal::VariableRepository;
using dns::dal::VariableRow;
using dns::dal::ViewRepository;
using dns::dal::ZoneRepository;

namespace {

std::string getDbUrl() {
  const char* pUrl = std::getenv("DNS_DB_URL");
  return pUrl ? std::string(pUrl) : std::string{};
}

}  // namespace

class VariableRepositoryTest : public ::testing::Test {
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
    _varRepo = std::make_unique<VariableRepository>(*_cpPool);

    auto cg = _cpPool->checkout();
    pqxx::work txn(*cg);
    txn.exec("DELETE FROM records");
    txn.exec("DELETE FROM variables");
    txn.exec("DELETE FROM deployments");
    txn.exec("DELETE FROM zones");
    txn.exec("DELETE FROM view_providers");
    txn.exec("DELETE FROM views");
    txn.commit();

    _iViewId = _vrRepo->create("var-view", "For variable tests");
    _iZoneId = _zrRepo->create("example.com", _iViewId, std::nullopt);
  }

  std::string _sDbUrl;
  std::unique_ptr<ConnectionPool> _cpPool;
  std::unique_ptr<ViewRepository> _vrRepo;
  std::unique_ptr<ZoneRepository> _zrRepo;
  std::unique_ptr<VariableRepository> _varRepo;
  int64_t _iViewId = 0;
  int64_t _iZoneId = 0;
};

TEST_F(VariableRepositoryTest, CreateGlobalAndFind) {
  int64_t iId = _varRepo->create("LB_VIP", "10.0.0.1", "ipv4", "global", std::nullopt);
  EXPECT_GT(iId, 0);

  auto oRow = _varRepo->findById(iId);
  ASSERT_TRUE(oRow.has_value());
  EXPECT_EQ(oRow->sName, "LB_VIP");
  EXPECT_EQ(oRow->sValue, "10.0.0.1");
  EXPECT_EQ(oRow->sType, "ipv4");
  EXPECT_EQ(oRow->sScope, "global");
  EXPECT_FALSE(oRow->oZoneId.has_value());
}

TEST_F(VariableRepositoryTest, CreateZoneScopedAndFind) {
  int64_t iId = _varRepo->create("MX_TARGET", "mail.example.com", "target",
                                 "zone", _iZoneId);
  EXPECT_GT(iId, 0);

  auto oRow = _varRepo->findById(iId);
  ASSERT_TRUE(oRow.has_value());
  EXPECT_EQ(oRow->sScope, "zone");
  ASSERT_TRUE(oRow->oZoneId.has_value());
  EXPECT_EQ(*oRow->oZoneId, _iZoneId);
}

TEST_F(VariableRepositoryTest, ListByZoneIdIncludesGlobals) {
  _varRepo->create("GLOBAL_VAR", "global-val", "string", "global", std::nullopt);
  _varRepo->create("ZONE_VAR", "zone-val", "string", "zone", _iZoneId);

  auto vRows = _varRepo->listByZoneId(_iZoneId);
  EXPECT_EQ(vRows.size(), 2u);
}

TEST_F(VariableRepositoryTest, ListByScope) {
  _varRepo->create("G1", "v1", "string", "global", std::nullopt);
  _varRepo->create("Z1", "v2", "string", "zone", _iZoneId);

  auto vGlobal = _varRepo->listByScope("global");
  EXPECT_EQ(vGlobal.size(), 1u);
  EXPECT_EQ(vGlobal[0].sName, "G1");
}

TEST_F(VariableRepositoryTest, UpdateValue) {
  int64_t iId = _varRepo->create("UPD", "old", "string", "global", std::nullopt);
  _varRepo->update(iId, "new");

  auto oRow = _varRepo->findById(iId);
  ASSERT_TRUE(oRow.has_value());
  EXPECT_EQ(oRow->sValue, "new");
}

TEST_F(VariableRepositoryTest, ScopeMismatchThrows) {
  // scope='global' with zone_id set should throw
  EXPECT_THROW(_varRepo->create("BAD", "v", "string", "global", _iZoneId),
               dns::common::ValidationError);
}

TEST_F(VariableRepositoryTest, DuplicateNameSameZoneThrows) {
  _varRepo->create("DUP", "v1", "string", "zone", _iZoneId);
  EXPECT_THROW(_varRepo->create("DUP", "v2", "string", "zone", _iZoneId),
               dns::common::ConflictError);
}
