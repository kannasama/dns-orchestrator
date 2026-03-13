#include "security/FederatedAuthService.hpp"

#include "common/Errors.hpp"
#include "common/Logger.hpp"
#include "dal/ConnectionPool.hpp"
#include "dal/GroupRepository.hpp"
#include "dal/IdpRepository.hpp"
#include "dal/RoleRepository.hpp"
#include "dal/SessionRepository.hpp"
#include "dal/UserRepository.hpp"
#include "security/CryptoService.hpp"
#include "security/HmacJwtSigner.hpp"

#include <gtest/gtest.h>

#include <cstdlib>
#include <memory>
#include <string>

using dns::dal::ConnectionPool;
using dns::dal::GroupRepository;
using dns::dal::IdpRepository;
using dns::dal::RoleRepository;
using dns::dal::SessionRepository;
using dns::dal::UserRepository;
using dns::security::CryptoService;
using dns::security::FederatedAuthService;
using dns::security::HmacJwtSigner;

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

class FederatedAuthIntegrationTest : public ::testing::Test {
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
    _upSigner = std::make_unique<HmacJwtSigner>("test-jwt-secret-for-federated-auth");
    _upUserRepo = std::make_unique<UserRepository>(*_upPool);
    _upGroupRepo = std::make_unique<GroupRepository>(*_upPool);
    _upRoleRepo = std::make_unique<RoleRepository>(*_upPool);
    _upSessionRepo = std::make_unique<SessionRepository>(*_upPool);
    _upIdpRepo = std::make_unique<IdpRepository>(*_upPool, *_upCrypto);

    _upFedAuth = std::make_unique<FederatedAuthService>(
        *_upUserRepo, *_upGroupRepo, *_upRoleRepo, *_upSessionRepo,
        *_upSigner, 3600, 86400);

    // Clean up test data
    auto cg = _upPool->checkout();
    pqxx::work txn(*cg);
    txn.exec("DELETE FROM sessions WHERE user_id IN "
             "(SELECT id FROM users WHERE username LIKE 'test-fed-%')");
    txn.exec("DELETE FROM group_members WHERE user_id IN "
             "(SELECT id FROM users WHERE username LIKE 'test-fed-%')");
    txn.exec("DELETE FROM users WHERE username LIKE 'test-fed-%'");
    txn.exec("DELETE FROM identity_providers WHERE name LIKE 'test-%'");
    txn.exec("DELETE FROM groups WHERE name LIKE 'test-fed-%'");
    txn.commit();
  }

  std::string _sDbUrl;
  std::string _sMasterKey;
  std::unique_ptr<ConnectionPool> _upPool;
  std::unique_ptr<CryptoService> _upCrypto;
  std::unique_ptr<HmacJwtSigner> _upSigner;
  std::unique_ptr<UserRepository> _upUserRepo;
  std::unique_ptr<GroupRepository> _upGroupRepo;
  std::unique_ptr<RoleRepository> _upRoleRepo;
  std::unique_ptr<SessionRepository> _upSessionRepo;
  std::unique_ptr<IdpRepository> _upIdpRepo;
  std::unique_ptr<FederatedAuthService> _upFedAuth;
};

TEST_F(FederatedAuthIntegrationTest, ProvisionNewOidcUser) {
  auto lr = _upFedAuth->processFederatedLogin(
      "oidc", "oidc|new-user-123", "test-fed-oidc-new", "oidc@test.com",
      {}, {}, 0);

  EXPECT_FALSE(lr.sToken.empty());
  EXPECT_GT(lr.iUserId, 0);
  EXPECT_EQ(lr.sUsername, "test-fed-oidc-new");
  EXPECT_TRUE(lr.bNewUser);

  // Verify user in DB
  auto oUser = _upUserRepo->findById(lr.iUserId);
  ASSERT_TRUE(oUser.has_value());
  EXPECT_EQ(oUser->sAuthMethod, "oidc");
}

TEST_F(FederatedAuthIntegrationTest, ProvisionNewSamlUser) {
  auto lr = _upFedAuth->processFederatedLogin(
      "saml", "saml-name-id-456", "test-fed-saml-new", "saml@test.com",
      {}, {}, 0);

  EXPECT_FALSE(lr.sToken.empty());
  EXPECT_GT(lr.iUserId, 0);
  EXPECT_EQ(lr.sUsername, "test-fed-saml-new");
  EXPECT_TRUE(lr.bNewUser);

  auto oUser = _upUserRepo->findById(lr.iUserId);
  ASSERT_TRUE(oUser.has_value());
  EXPECT_EQ(oUser->sAuthMethod, "saml");
}

TEST_F(FederatedAuthIntegrationTest, ExistingUserUpdatesEmail) {
  // First login creates user
  auto lr1 = _upFedAuth->processFederatedLogin(
      "oidc", "oidc|email-update", "test-fed-email-update", "old@test.com",
      {}, {}, 0);
  EXPECT_TRUE(lr1.bNewUser);

  // Second login with new email
  auto lr2 = _upFedAuth->processFederatedLogin(
      "oidc", "oidc|email-update", "test-fed-email-update", "new@test.com",
      {}, {}, 0);
  EXPECT_FALSE(lr2.bNewUser);
  EXPECT_EQ(lr2.iUserId, lr1.iUserId);

  // Verify email updated
  auto oUser = _upUserRepo->findById(lr2.iUserId);
  ASSERT_TRUE(oUser.has_value());
  EXPECT_EQ(oUser->sEmail, "new@test.com");
}

TEST_F(FederatedAuthIntegrationTest, DisabledUserRejected) {
  // Create user
  auto lr = _upFedAuth->processFederatedLogin(
      "oidc", "oidc|disabled-user", "test-fed-disabled", "disabled@test.com",
      {}, {}, 0);

  // Deactivate
  _upUserRepo->deactivate(lr.iUserId);

  // Try to login again — should throw
  EXPECT_THROW(
      _upFedAuth->processFederatedLogin(
          "oidc", "oidc|disabled-user", "test-fed-disabled", "disabled@test.com",
          {}, {}, 0),
      dns::common::AuthenticationError);
}

TEST_F(FederatedAuthIntegrationTest, GroupMappingAssignsCorrectGroups) {
  // Create a test group
  int64_t iGroupId = _upGroupRepo->create("test-fed-dns-admins", "Test DNS Admins");

  nlohmann::json jMappings = {
      {"rules", nlohmann::json::array({
          {{"idp_group", "dns-admins"}, {"meridian_group_id", iGroupId}},
      })},
  };

  auto lr = _upFedAuth->processFederatedLogin(
      "oidc", "oidc|group-mapped", "test-fed-group-mapped", "group@test.com",
      {"dns-admins", "other-group"}, jMappings, 0);

  // Verify user is in the group
  auto vGroups = _upUserRepo->listGroupsForUser(lr.iUserId);
  bool bFound = false;
  for (const auto& [iGid, sName] : vGroups) {
    if (iGid == iGroupId) {
      bFound = true;
      break;
    }
  }
  EXPECT_TRUE(bFound) << "User should be assigned to test-fed-dns-admins group";
}

TEST_F(FederatedAuthIntegrationTest, GroupMappingWildcard) {
  int64_t iGroupId = _upGroupRepo->create("test-fed-platform", "Test Platform");

  nlohmann::json jMappings = {
      {"rules", nlohmann::json::array({
          {{"idp_group", "platform-*"}, {"meridian_group_id", iGroupId}},
      })},
  };

  auto lr = _upFedAuth->processFederatedLogin(
      "oidc", "oidc|wildcard-test", "test-fed-wildcard", "wild@test.com",
      {"platform-team"}, jMappings, 0);

  auto vGroups = _upUserRepo->listGroupsForUser(lr.iUserId);
  bool bFound = false;
  for (const auto& [iGid, sName] : vGroups) {
    if (iGid == iGroupId) {
      bFound = true;
      break;
    }
  }
  EXPECT_TRUE(bFound) << "Wildcard platform-* should match platform-team";
}

TEST_F(FederatedAuthIntegrationTest, GroupMappingFallsBackToDefault) {
  int64_t iDefaultGroupId = _upGroupRepo->create("test-fed-default", "Test Default");

  nlohmann::json jMappings = {
      {"rules", nlohmann::json::array({
          {{"idp_group", "nonexistent-group"}, {"meridian_group_id", 99999}},
      })},
  };

  auto lr = _upFedAuth->processFederatedLogin(
      "oidc", "oidc|default-group", "test-fed-default-group", "default@test.com",
      {"some-other-group"}, jMappings, iDefaultGroupId);

  auto vGroups = _upUserRepo->listGroupsForUser(lr.iUserId);
  bool bFound = false;
  for (const auto& [iGid, sName] : vGroups) {
    if (iGid == iDefaultGroupId) {
      bFound = true;
      break;
    }
  }
  EXPECT_TRUE(bFound) << "User should fall back to default group";
}

TEST_F(FederatedAuthIntegrationTest, IdpCrudWithEncryptedSecret) {
  nlohmann::json jConfig = {
      {"issuer_url", "https://test-crud.example.com"},
      {"client_id", "test-crud-client"},
  };

  int64_t iId = _upIdpRepo->create("test-crud-idp", "oidc", jConfig,
                                     "my-super-secret", {}, 0);
  EXPECT_GT(iId, 0);

  // Verify secret is encrypted in DB (not plaintext)
  auto cg = _upPool->checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT encrypted_secret FROM identity_providers WHERE id = $1",
      pqxx::params{iId});
  txn.commit();

  ASSERT_FALSE(result.empty());
  std::string sEncrypted = result[0][0].as<std::string>("");
  EXPECT_FALSE(sEncrypted.empty());
  EXPECT_NE(sEncrypted, "my-super-secret");  // Should be encrypted, not plaintext

  // Verify decrypted via repository
  auto oIdp = _upIdpRepo->findById(iId);
  ASSERT_TRUE(oIdp.has_value());
  EXPECT_EQ(oIdp->sDecryptedSecret, "my-super-secret");
}
