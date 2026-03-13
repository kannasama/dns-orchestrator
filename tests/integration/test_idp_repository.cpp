#include "dal/IdpRepository.hpp"

#include "common/Logger.hpp"
#include "dal/ConnectionPool.hpp"
#include "security/CryptoService.hpp"

#include <gtest/gtest.h>

#include <cstdlib>
#include <memory>
#include <string>

using dns::dal::ConnectionPool;
using dns::dal::IdpRepository;
using dns::dal::IdpRow;
using dns::security::CryptoService;

namespace {

std::string getDbUrl() {
  const char* pUrl = std::getenv("DNS_DB_URL");
  return pUrl ? std::string(pUrl) : std::string{};
}

std::string getMasterKey() {
  const char* pKey = std::getenv("DNS_MASTER_KEY");
  return pKey ? std::string(pKey) : std::string{};
}

}  // namespace

class IdpRepositoryTest : public ::testing::Test {
 protected:
  void SetUp() override {
    _sDbUrl = getDbUrl();
    _sMasterKey = getMasterKey();
    if (_sDbUrl.empty() || _sMasterKey.empty()) {
      GTEST_SKIP() << "DNS_DB_URL or DNS_MASTER_KEY not set — skipping integration test";
    }
    dns::common::Logger::init("warn");

    _upPool = std::make_unique<ConnectionPool>(_sDbUrl, 2);
    _upCrypto = std::make_unique<CryptoService>(_sMasterKey);
    _upRepo = std::make_unique<IdpRepository>(*_upPool, *_upCrypto);

    // Clean up test data
    auto cg = _upPool->checkout();
    pqxx::work txn(*cg);
    txn.exec("DELETE FROM identity_providers WHERE name LIKE 'test-%'");
    txn.commit();
  }

  std::string _sDbUrl;
  std::string _sMasterKey;
  std::unique_ptr<ConnectionPool> _upPool;
  std::unique_ptr<CryptoService> _upCrypto;
  std::unique_ptr<IdpRepository> _upRepo;
};

TEST_F(IdpRepositoryTest, CreateAndFindOidc) {
  nlohmann::json jConfig = {
      {"issuer_url", "https://accounts.google.com"},
      {"client_id", "test-client-id"},
      {"redirect_uri", "http://localhost:8080/api/v1/auth/oidc/1/callback"},
      {"scopes", nlohmann::json::array({"openid", "email", "profile"})},
  };
  nlohmann::json jMappings = {
      {"rules", nlohmann::json::array({
          {{"idp_group", "dns-admins"}, {"meridian_group_id", 1}},
      })},
  };

  int64_t iId = _upRepo->create("test-oidc-provider", "oidc", jConfig,
                                 "super-secret-client-secret", jMappings, 0);
  EXPECT_GT(iId, 0);

  auto oRow = _upRepo->findById(iId);
  ASSERT_TRUE(oRow.has_value());
  EXPECT_EQ(oRow->sName, "test-oidc-provider");
  EXPECT_EQ(oRow->sType, "oidc");
  EXPECT_TRUE(oRow->bIsEnabled);
  EXPECT_EQ(oRow->jConfig["issuer_url"], "https://accounts.google.com");
  EXPECT_EQ(oRow->jConfig["client_id"], "test-client-id");
  EXPECT_EQ(oRow->sDecryptedSecret, "super-secret-client-secret");
  EXPECT_EQ(oRow->jGroupMappings["rules"].size(), 1);
}

TEST_F(IdpRepositoryTest, ListEnabledDoesNotExposeSecret) {
  nlohmann::json jConfig = {{"issuer_url", "https://example.com"}};
  _upRepo->create("test-list-idp", "oidc", jConfig, "my-secret", {}, 0);

  auto vRows = _upRepo->listEnabled();
  ASSERT_FALSE(vRows.empty());

  bool bFound = false;
  for (const auto& row : vRows) {
    if (row.sName == "test-list-idp") {
      bFound = true;
      EXPECT_TRUE(row.sDecryptedSecret.empty());
      break;
    }
  }
  EXPECT_TRUE(bFound);
}

TEST_F(IdpRepositoryTest, UpdateIdp) {
  nlohmann::json jConfig = {{"issuer_url", "https://old.example.com"}};
  int64_t iId = _upRepo->create("test-update-idp", "oidc", jConfig, "old-secret", {}, 0);

  nlohmann::json jNewConfig = {{"issuer_url", "https://new.example.com"}};
  _upRepo->update(iId, "test-update-idp-renamed", true, jNewConfig,
                  "new-secret", {}, 0);

  auto oRow = _upRepo->findById(iId);
  ASSERT_TRUE(oRow.has_value());
  EXPECT_EQ(oRow->sName, "test-update-idp-renamed");
  EXPECT_EQ(oRow->jConfig["issuer_url"], "https://new.example.com");
  EXPECT_EQ(oRow->sDecryptedSecret, "new-secret");
}

TEST_F(IdpRepositoryTest, DeleteIdp) {
  nlohmann::json jConfig = {{"issuer_url", "https://delete.example.com"}};
  int64_t iId = _upRepo->create("test-delete-idp", "oidc", jConfig, "secret", {}, 0);

  _upRepo->deleteIdp(iId);

  auto oRow = _upRepo->findById(iId);
  EXPECT_FALSE(oRow.has_value());
}
