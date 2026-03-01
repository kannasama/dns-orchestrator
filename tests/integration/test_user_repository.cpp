#include "dal/UserRepository.hpp"

#include "common/Logger.hpp"
#include "dal/ConnectionPool.hpp"

#include <gtest/gtest.h>

#include <cstdlib>
#include <string>

using dns::dal::ConnectionPool;
using dns::dal::UserRepository;
using dns::dal::UserRow;

namespace {

std::string getDbUrl() {
  const char* pUrl = std::getenv("DNS_DB_URL");
  return pUrl ? std::string(pUrl) : std::string{};
}

}  // namespace

class UserRepositoryTest : public ::testing::Test {
 protected:
  void SetUp() override {
    _sDbUrl = getDbUrl();
    if (_sDbUrl.empty()) {
      GTEST_SKIP() << "DNS_DB_URL not set — skipping integration test";
    }
    dns::common::Logger::init("warn");
    _cpPool = std::make_unique<ConnectionPool>(_sDbUrl, 2);
    _urRepo = std::make_unique<UserRepository>(*_cpPool);

    // Clean test data
    auto cg = _cpPool->checkout();
    pqxx::work txn(*cg);
    txn.exec("DELETE FROM group_members");
    txn.exec("DELETE FROM sessions");
    txn.exec("DELETE FROM api_keys");
    txn.exec("DELETE FROM deployments");
    txn.exec("DELETE FROM users");
    txn.exec("DELETE FROM groups");
    txn.commit();
  }

  std::string _sDbUrl;
  std::unique_ptr<ConnectionPool> _cpPool;
  std::unique_ptr<UserRepository> _urRepo;
};

TEST_F(UserRepositoryTest, CreateAndFindByUsername) {
  int64_t iId = _urRepo->create("alice", "alice@example.com", "$argon2id$v=19$m=65536,t=3,p=1$fakesalt$fakehash");

  EXPECT_GT(iId, 0);

  auto oUser = _urRepo->findByUsername("alice");
  ASSERT_TRUE(oUser.has_value());
  EXPECT_EQ(oUser->iId, iId);
  EXPECT_EQ(oUser->sUsername, "alice");
  EXPECT_EQ(oUser->sEmail, "alice@example.com");
  EXPECT_EQ(oUser->sAuthMethod, "local");
  EXPECT_TRUE(oUser->bIsActive);
}

TEST_F(UserRepositoryTest, FindByUsernameReturnsNulloptForMissing) {
  auto oUser = _urRepo->findByUsername("nonexistent");
  EXPECT_FALSE(oUser.has_value());
}

TEST_F(UserRepositoryTest, FindByIdWorks) {
  int64_t iId = _urRepo->create("bob", "bob@example.com", "hash123");

  auto oUser = _urRepo->findById(iId);
  ASSERT_TRUE(oUser.has_value());
  EXPECT_EQ(oUser->sUsername, "bob");
}

TEST_F(UserRepositoryTest, GetHighestRoleReturnsAdminOverOperator) {
  int64_t iUserId = _urRepo->create("carol", "carol@example.com", "hash");

  // Create groups and memberships
  auto cg = _cpPool->checkout();
  pqxx::work txn(*cg);
  auto rOp = txn.exec("INSERT INTO groups (name, role) VALUES ('operators', 'operator') RETURNING id").one_row();
  auto rAdmin = txn.exec("INSERT INTO groups (name, role) VALUES ('admins', 'admin') RETURNING id").one_row();
  txn.exec("INSERT INTO group_members (user_id, group_id) VALUES ($1, $2)",
           pqxx::params{iUserId, rOp[0].as<int64_t>()});
  txn.exec("INSERT INTO group_members (user_id, group_id) VALUES ($1, $2)",
           pqxx::params{iUserId, rAdmin[0].as<int64_t>()});
  txn.commit();

  std::string sRole = _urRepo->getHighestRole(iUserId);
  EXPECT_EQ(sRole, "admin");
}

TEST_F(UserRepositoryTest, GetHighestRoleReturnsEmptyForNoGroups) {
  int64_t iUserId = _urRepo->create("dave", "dave@example.com", "hash");
  std::string sRole = _urRepo->getHighestRole(iUserId);
  EXPECT_TRUE(sRole.empty());
}
