#include "dal/RoleRepository.hpp"
#include "dal/ConnectionPool.hpp"
#include "common/Errors.hpp"
#include "common/Logger.hpp"

#include <gtest/gtest.h>

#include <cstdlib>
#include <memory>
#include <string>

namespace {
std::string getDbUrl() {
  const char* p = std::getenv("DNS_DB_URL");
  return p ? std::string(p) : "";
}
}  // namespace

class RoleRepositoryTest : public ::testing::Test {
 protected:
  void SetUp() override {
    _sDbUrl = getDbUrl();
    if (_sDbUrl.empty()) {
      GTEST_SKIP() << "DNS_DB_URL not set — skipping DB integration test";
    }
    dns::common::Logger::init("warn");
    _cpPool = std::make_unique<dns::dal::ConnectionPool>(_sDbUrl, 2);
    _rrRepo = std::make_unique<dns::dal::RoleRepository>(*_cpPool);

    // Clean test roles (leave system roles alone)
    auto cg = _cpPool->checkout();
    pqxx::work txn(*cg);
    txn.exec("DELETE FROM roles WHERE name LIKE 'test_%' AND is_system = false");
    txn.commit();
  }

  std::string _sDbUrl;
  std::unique_ptr<dns::dal::ConnectionPool> _cpPool;
  std::unique_ptr<dns::dal::RoleRepository> _rrRepo;
};

TEST_F(RoleRepositoryTest, ListAll_ReturnsSystemRoles) {
  auto vRoles = _rrRepo->listAll();
  EXPECT_GE(vRoles.size(), 3u);  // Admin, Operator, Viewer

  bool bFoundAdmin = false, bFoundOperator = false, bFoundViewer = false;
  for (const auto& role : vRoles) {
    if (role.sName == "Admin") bFoundAdmin = true;
    if (role.sName == "Operator") bFoundOperator = true;
    if (role.sName == "Viewer") bFoundViewer = true;
  }
  EXPECT_TRUE(bFoundAdmin);
  EXPECT_TRUE(bFoundOperator);
  EXPECT_TRUE(bFoundViewer);
}

TEST_F(RoleRepositoryTest, CreateAndFindById) {
  int64_t iId = _rrRepo->create("test_custom_role", "A test role");
  EXPECT_GT(iId, 0);

  auto oRole = _rrRepo->findById(iId);
  ASSERT_TRUE(oRole.has_value());
  EXPECT_EQ(oRole->sName, "test_custom_role");
  EXPECT_EQ(oRole->sDescription, "A test role");
  EXPECT_FALSE(oRole->bIsSystem);
}

TEST_F(RoleRepositoryTest, FindByName) {
  auto oRole = _rrRepo->findByName("Admin");
  ASSERT_TRUE(oRole.has_value());
  EXPECT_TRUE(oRole->bIsSystem);
}

TEST_F(RoleRepositoryTest, CreateDuplicateName_Throws) {
  _rrRepo->create("test_dup_role", "first");
  EXPECT_THROW(_rrRepo->create("test_dup_role", "second"), dns::common::ConflictError);
}

TEST_F(RoleRepositoryTest, Update_CustomRole) {
  int64_t iId = _rrRepo->create("test_update_role", "before");
  _rrRepo->update(iId, "test_update_role_renamed", "after");

  auto oRole = _rrRepo->findById(iId);
  ASSERT_TRUE(oRole.has_value());
  EXPECT_EQ(oRole->sName, "test_update_role_renamed");
  EXPECT_EQ(oRole->sDescription, "after");
}

TEST_F(RoleRepositoryTest, Update_SystemRoleRename_Throws) {
  auto oAdmin = _rrRepo->findByName("Admin");
  ASSERT_TRUE(oAdmin.has_value());
  EXPECT_THROW(_rrRepo->update(oAdmin->iId, "SuperAdmin", "renamed"),
               dns::common::ValidationError);
}

TEST_F(RoleRepositoryTest, DeleteRole_CustomRole) {
  int64_t iId = _rrRepo->create("test_delete_role", "to be deleted");
  _rrRepo->deleteRole(iId);
  EXPECT_FALSE(_rrRepo->findById(iId).has_value());
}

TEST_F(RoleRepositoryTest, DeleteRole_SystemRole_Throws) {
  auto oAdmin = _rrRepo->findByName("Admin");
  ASSERT_TRUE(oAdmin.has_value());
  EXPECT_THROW(_rrRepo->deleteRole(oAdmin->iId), dns::common::ConflictError);
}

TEST_F(RoleRepositoryTest, GetPermissions_AdminHasAll) {
  auto oAdmin = _rrRepo->findByName("Admin");
  ASSERT_TRUE(oAdmin.has_value());
  auto perms = _rrRepo->getPermissions(oAdmin->iId);
  EXPECT_GT(perms.size(), 30u);  // Admin should have all permissions
  EXPECT_TRUE(perms.count("zones.view"));
  EXPECT_TRUE(perms.count("settings.edit"));
  EXPECT_TRUE(perms.count("backup.restore"));
}

TEST_F(RoleRepositoryTest, GetPermissions_ViewerSubset) {
  auto oViewer = _rrRepo->findByName("Viewer");
  ASSERT_TRUE(oViewer.has_value());
  auto perms = _rrRepo->getPermissions(oViewer->iId);
  EXPECT_TRUE(perms.count("zones.view"));
  EXPECT_FALSE(perms.count("zones.create"));
  EXPECT_FALSE(perms.count("settings.edit"));
}

TEST_F(RoleRepositoryTest, SetPermissions_ReplacesAll) {
  int64_t iId = _rrRepo->create("test_perms_role", "for permissions");
  _rrRepo->setPermissions(iId, {"zones.view", "zones.create"});

  auto perms = _rrRepo->getPermissions(iId);
  EXPECT_EQ(perms.size(), 2u);
  EXPECT_TRUE(perms.count("zones.view"));
  EXPECT_TRUE(perms.count("zones.create"));

  // Replace with different set
  _rrRepo->setPermissions(iId, {"records.view"});
  perms = _rrRepo->getPermissions(iId);
  EXPECT_EQ(perms.size(), 1u);
  EXPECT_TRUE(perms.count("records.view"));
  EXPECT_FALSE(perms.count("zones.view"));
}

TEST_F(RoleRepositoryTest, GetHighestRoleName_NoMembership) {
  auto sRole = _rrRepo->getHighestRoleName(999999);
  EXPECT_TRUE(sRole.empty());
}
