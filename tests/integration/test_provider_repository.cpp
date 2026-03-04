#include "dal/ProviderRepository.hpp"

#include "common/Errors.hpp"
#include "common/Logger.hpp"
#include "dal/ConnectionPool.hpp"
#include "security/CryptoService.hpp"

#include <gtest/gtest.h>

#include <cstdlib>
#include <string>

using dns::dal::ConnectionPool;
using dns::dal::ProviderRepository;
using dns::dal::ProviderRow;

namespace {

std::string getDbUrl() {
  const char* pUrl = std::getenv("DNS_DB_URL");
  return pUrl ? std::string(pUrl) : std::string{};
}

// 64-char hex key for CryptoService tests
const std::string kTestMasterKey =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

}  // namespace

class ProviderRepositoryTest : public ::testing::Test {
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

    // Clean test data
    auto cg = _cpPool->checkout();
    pqxx::work txn(*cg);
    txn.exec("DELETE FROM view_providers");
    txn.exec("DELETE FROM providers");
    txn.commit();
  }

  std::string _sDbUrl;
  std::unique_ptr<ConnectionPool> _cpPool;
  std::unique_ptr<dns::security::CryptoService> _csService;
  std::unique_ptr<ProviderRepository> _prRepo;
};

TEST_F(ProviderRepositoryTest, CreateAndFindById) {
  int64_t iId = _prRepo->create("test-pdns", "powerdns",
                                "http://localhost:8081", "secret-api-key");
  EXPECT_GT(iId, 0);

  auto oRow = _prRepo->findById(iId);
  ASSERT_TRUE(oRow.has_value());
  EXPECT_EQ(oRow->iId, iId);
  EXPECT_EQ(oRow->sName, "test-pdns");
  EXPECT_EQ(oRow->sType, "powerdns");
  EXPECT_EQ(oRow->sApiEndpoint, "http://localhost:8081");
  EXPECT_EQ(oRow->sDecryptedToken, "secret-api-key");
}

TEST_F(ProviderRepositoryTest, ListAll) {
  _prRepo->create("pdns-1", "powerdns", "http://pdns1:8081", "key1");
  _prRepo->create("pdns-2", "powerdns", "http://pdns2:8081", "key2");

  auto vRows = _prRepo->listAll();
  EXPECT_EQ(vRows.size(), 2u);
}

TEST_F(ProviderRepositoryTest, UpdateWithToken) {
  int64_t iId = _prRepo->create("old-name", "powerdns", "http://old:8081", "old-key");

  _prRepo->update(iId, "new-name", "http://new:8081",
                  std::optional<std::string>("new-key"));

  auto oRow = _prRepo->findById(iId);
  ASSERT_TRUE(oRow.has_value());
  EXPECT_EQ(oRow->sName, "new-name");
  EXPECT_EQ(oRow->sApiEndpoint, "http://new:8081");
  EXPECT_EQ(oRow->sDecryptedToken, "new-key");
}

TEST_F(ProviderRepositoryTest, UpdateWithoutToken) {
  int64_t iId = _prRepo->create("keep-token", "powerdns",
                                "http://keep:8081", "original-key");

  _prRepo->update(iId, "renamed", "http://renamed:8081", std::nullopt);

  auto oRow = _prRepo->findById(iId);
  ASSERT_TRUE(oRow.has_value());
  EXPECT_EQ(oRow->sName, "renamed");
  EXPECT_EQ(oRow->sDecryptedToken, "original-key");
}

TEST_F(ProviderRepositoryTest, DeleteById) {
  int64_t iId = _prRepo->create("to-delete", "powerdns",
                                "http://del:8081", "key");

  _prRepo->deleteById(iId);

  auto oRow = _prRepo->findById(iId);
  EXPECT_FALSE(oRow.has_value());
}

TEST_F(ProviderRepositoryTest, DuplicateNameThrows) {
  _prRepo->create("unique-name", "powerdns", "http://a:8081", "key1");

  EXPECT_THROW(_prRepo->create("unique-name", "powerdns", "http://b:8081", "key2"),
               dns::common::ConflictError);
}
