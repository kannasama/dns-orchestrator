#include "dal/ViewRepository.hpp"

#include "common/Errors.hpp"
#include "common/Logger.hpp"
#include "dal/ConnectionPool.hpp"
#include "dal/ProviderRepository.hpp"
#include "security/CryptoService.hpp"

#include <gtest/gtest.h>

#include <cstdlib>
#include <string>

using dns::dal::ConnectionPool;
using dns::dal::ProviderRepository;
using dns::dal::ViewRepository;
using dns::dal::ViewRow;

namespace {

std::string getDbUrl() {
  const char* pUrl = std::getenv("DNS_DB_URL");
  return pUrl ? std::string(pUrl) : std::string{};
}

const std::string kTestMasterKey =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

}  // namespace

class ViewRepositoryTest : public ::testing::Test {
 protected:
  void SetUp() override {
    _sDbUrl = getDbUrl();
    if (_sDbUrl.empty()) {
      GTEST_SKIP() << "DNS_DB_URL not set — skipping integration test";
    }
    dns::common::Logger::init("warn");
    _cpPool = std::make_unique<ConnectionPool>(_sDbUrl, 2);
    _csService = std::make_unique<dns::security::CryptoService>(kTestMasterKey);
    _prRepo = std::make_unique<ProviderRepository>(*_cpPool, *_csService);
    _vrRepo = std::make_unique<ViewRepository>(*_cpPool);

    // Clean test data (respect FK order)
    auto cg = _cpPool->checkout();
    pqxx::work txn(*cg);
    txn.exec("DELETE FROM records");
    txn.exec("DELETE FROM variables");
    txn.exec("DELETE FROM deployments");
    txn.exec("DELETE FROM zones");
    txn.exec("DELETE FROM view_providers");
    txn.exec("DELETE FROM views");
    txn.exec("DELETE FROM providers");
    txn.commit();
  }

  std::string _sDbUrl;
  std::unique_ptr<ConnectionPool> _cpPool;
  std::unique_ptr<dns::security::CryptoService> _csService;
  std::unique_ptr<ProviderRepository> _prRepo;
  std::unique_ptr<ViewRepository> _vrRepo;
};

TEST_F(ViewRepositoryTest, CreateAndFindById) {
  int64_t iId = _vrRepo->create("internal", "Internal DNS view");
  EXPECT_GT(iId, 0);

  auto oRow = _vrRepo->findById(iId);
  ASSERT_TRUE(oRow.has_value());
  EXPECT_EQ(oRow->iId, iId);
  EXPECT_EQ(oRow->sName, "internal");
  EXPECT_EQ(oRow->sDescription, "Internal DNS view");
  EXPECT_TRUE(oRow->vProviderIds.empty());
}

TEST_F(ViewRepositoryTest, FindWithProviders) {
  int64_t iViewId = _vrRepo->create("multi-provider", "View with providers");
  int64_t iProv1 = _prRepo->create("pdns-1", "powerdns", "http://p1:8081", "k1");
  int64_t iProv2 = _prRepo->create("pdns-2", "powerdns", "http://p2:8081", "k2");

  _vrRepo->attachProvider(iViewId, iProv1);
  _vrRepo->attachProvider(iViewId, iProv2);

  auto oRow = _vrRepo->findWithProviders(iViewId);
  ASSERT_TRUE(oRow.has_value());
  EXPECT_EQ(oRow->vProviderIds.size(), 2u);
}

TEST_F(ViewRepositoryTest, AttachDetach) {
  int64_t iViewId = _vrRepo->create("attach-test", "test");
  int64_t iProvId = _prRepo->create("pdns-ad", "powerdns", "http://ad:8081", "k");

  _vrRepo->attachProvider(iViewId, iProvId);
  auto oRow = _vrRepo->findWithProviders(iViewId);
  ASSERT_TRUE(oRow.has_value());
  EXPECT_EQ(oRow->vProviderIds.size(), 1u);

  _vrRepo->detachProvider(iViewId, iProvId);
  oRow = _vrRepo->findWithProviders(iViewId);
  ASSERT_TRUE(oRow.has_value());
  EXPECT_TRUE(oRow->vProviderIds.empty());
}

TEST_F(ViewRepositoryTest, DeleteCascadesViewProviders) {
  int64_t iViewId = _vrRepo->create("cascade-test", "test");
  int64_t iProvId = _prRepo->create("pdns-casc", "powerdns", "http://c:8081", "k");
  _vrRepo->attachProvider(iViewId, iProvId);

  _vrRepo->deleteById(iViewId);

  // Verify view_providers rows are gone
  auto cg = _cpPool->checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec("SELECT COUNT(*) FROM view_providers WHERE view_id = $1",
                         pqxx::params{iViewId});
  txn.commit();
  EXPECT_EQ(result[0][0].as<int>(), 0);
}

TEST_F(ViewRepositoryTest, DeleteBlockedByZones) {
  int64_t iViewId = _vrRepo->create("blocked-view", "test");

  // Create a zone referencing this view
  auto cg = _cpPool->checkout();
  pqxx::work txn(*cg);
  txn.exec("INSERT INTO zones (name, view_id) VALUES ('example.com', $1)",
           pqxx::params{iViewId});
  txn.commit();

  EXPECT_THROW(_vrRepo->deleteById(iViewId), dns::common::ConflictError);
}

TEST_F(ViewRepositoryTest, DuplicateNameThrows) {
  _vrRepo->create("unique-view", "first");
  EXPECT_THROW(_vrRepo->create("unique-view", "second"), dns::common::ConflictError);
}
