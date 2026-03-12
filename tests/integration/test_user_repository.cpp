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

TEST_F(UserRepositoryTest, ListAllReturnsAllUsers) {
  _urRepo->create("alice", "alice@example.com", "hash1");
  _urRepo->create("bob", "bob@example.com", "hash2");

  auto vUsers = _urRepo->listAll();
  ASSERT_EQ(vUsers.size(), 2u);
  // Ordered by username
  EXPECT_EQ(vUsers[0].sUsername, "alice");
  EXPECT_EQ(vUsers[1].sUsername, "bob");
}

TEST_F(UserRepositoryTest, UpdateEmailAndActive) {
  int64_t iId = _urRepo->create("eve", "eve@example.com", "hash");

  _urRepo->update(iId, "eve-new@example.com", false);

  auto oUser = _urRepo->findById(iId);
  ASSERT_TRUE(oUser.has_value());
  EXPECT_EQ(oUser->sEmail, "eve-new@example.com");
  EXPECT_FALSE(oUser->bIsActive);
}

TEST_F(UserRepositoryTest, DeactivateUser) {
  int64_t iId = _urRepo->create("frank", "frank@example.com", "hash");

  _urRepo->deactivate(iId);

  auto oUser = _urRepo->findById(iId);
  ASSERT_TRUE(oUser.has_value());
  EXPECT_FALSE(oUser->bIsActive);
}

TEST_F(UserRepositoryTest, UpdatePassword) {
  int64_t iId = _urRepo->create("grace", "grace@example.com", "old-hash");

  _urRepo->updatePassword(iId, "new-hash");

  auto oUser = _urRepo->findById(iId);
  ASSERT_TRUE(oUser.has_value());
  EXPECT_EQ(oUser->sPasswordHash, "new-hash");
}

TEST_F(UserRepositoryTest, SetForcePasswordChange) {
  int64_t iId = _urRepo->create("heidi", "heidi@example.com", "hash");

  _urRepo->setForcePasswordChange(iId, true);
  auto oUser = _urRepo->findById(iId);
  ASSERT_TRUE(oUser.has_value());
  EXPECT_TRUE(oUser->bForcePasswordChange);

  _urRepo->setForcePasswordChange(iId, false);
  oUser = _urRepo->findById(iId);
  ASSERT_TRUE(oUser.has_value());
  EXPECT_FALSE(oUser->bForcePasswordChange);
}

TEST_F(UserRepositoryTest, AddRemoveGroupAndListGroups) {
  int64_t iUserId = _urRepo->create("ivan", "ivan@example.com", "hash");

  // Create groups and get a role ID
  auto cg = _cpPool->checkout();
  pqxx::work txn(*cg);
  auto r1 = txn.exec("INSERT INTO groups (name) VALUES ('grp-a') RETURNING id");
  auto r2 = txn.exec("INSERT INTO groups (name) VALUES ('grp-b') RETURNING id");
  int64_t iGrpA = r1.one_row()[0].as<int64_t>();
  int64_t iGrpB = r2.one_row()[0].as<int64_t>();
  auto rRole = txn.exec("SELECT id FROM roles WHERE name = 'Viewer'").one_row();
  int64_t iRoleId = rRole[0].as<int64_t>();
  txn.commit();

  _urRepo->addToGroup(iUserId, iGrpA, iRoleId);
  _urRepo->addToGroup(iUserId, iGrpB, iRoleId);

  auto vGroups = _urRepo->listGroupsForUser(iUserId);
  ASSERT_EQ(vGroups.size(), 2u);

  _urRepo->removeFromGroup(iUserId, iGrpA);
  vGroups = _urRepo->listGroupsForUser(iUserId);
  ASSERT_EQ(vGroups.size(), 1u);
  EXPECT_EQ(vGroups[0].first, iGrpB);
}
