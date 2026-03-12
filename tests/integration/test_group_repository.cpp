#include "dal/GroupRepository.hpp"

#include "common/Errors.hpp"
#include "common/Logger.hpp"
#include "dal/ConnectionPool.hpp"

#include <gtest/gtest.h>

#include <cstdlib>
#include <string>

using dns::dal::ConnectionPool;
using dns::dal::GroupRepository;

namespace {

std::string getDbUrl() {
  const char* pUrl = std::getenv("DNS_DB_URL");
  return pUrl ? std::string(pUrl) : std::string{};
}

}  // namespace

class GroupRepositoryTest : public ::testing::Test {
 protected:
  void SetUp() override {
    _sDbUrl = getDbUrl();
    if (_sDbUrl.empty()) {
      GTEST_SKIP() << "DNS_DB_URL not set — skipping integration test";
    }
    dns::common::Logger::init("warn");
    _cpPool = std::make_unique<ConnectionPool>(_sDbUrl, 2);
    _grRepo = std::make_unique<GroupRepository>(*_cpPool);

    auto cg = _cpPool->checkout();
    pqxx::work txn(*cg);
    txn.exec("DELETE FROM group_members");
    txn.exec("DELETE FROM groups WHERE name LIKE 'test-%'");
    txn.commit();
  }

  std::string _sDbUrl;
  std::unique_ptr<ConnectionPool> _cpPool;
  std::unique_ptr<GroupRepository> _grRepo;
};

TEST_F(GroupRepositoryTest, CreateAndFindById) {
  auto iId = _grRepo->create("test-admins", "Test admin group");
  auto oGroup = _grRepo->findById(iId);
  ASSERT_TRUE(oGroup.has_value());
  EXPECT_EQ(oGroup->sName, "test-admins");
  EXPECT_EQ(oGroup->sDescription, "Test admin group");
}

TEST_F(GroupRepositoryTest, ListAllWithMemberCount) {
  _grRepo->create("test-ops", "");
  auto vGroups = _grRepo->listAll();
  EXPECT_GE(vGroups.size(), 1u);
  auto it = std::find_if(vGroups.begin(), vGroups.end(),
      [](const auto& g) { return g.sName == "test-ops"; });
  ASSERT_NE(it, vGroups.end());
  EXPECT_EQ(it->iMemberCount, 0);
}

TEST_F(GroupRepositoryTest, UpdateGroup) {
  auto iId = _grRepo->create("test-old", "old desc");
  _grRepo->update(iId, "test-new", "new desc");
  auto oGroup = _grRepo->findById(iId);
  EXPECT_EQ(oGroup->sName, "test-new");
  EXPECT_EQ(oGroup->sDescription, "new desc");
}

TEST_F(GroupRepositoryTest, DeleteGroup) {
  auto iId = _grRepo->create("test-delete", "");
  _grRepo->deleteGroup(iId);
  auto oGroup = _grRepo->findById(iId);
  EXPECT_FALSE(oGroup.has_value());
}
