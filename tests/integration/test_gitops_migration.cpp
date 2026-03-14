#include "gitops/GitOpsMigration.hpp"

#include <gtest/gtest.h>
#include <cstdlib>
#include <pqxx/pqxx>

#include "common/Logger.hpp"
#include "dal/ConnectionPool.hpp"
#include "dal/GitRepoRepository.hpp"
#include "dal/ViewRepository.hpp"
#include "dal/ZoneRepository.hpp"
#include "security/CryptoService.hpp"

namespace {
std::string getDbUrl() {
  const char* pUrl = std::getenv("DNS_DB_URL");
  return pUrl ? std::string(pUrl) : std::string{};
}
const std::string kTestMasterKey =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
}  // namespace

class GitOpsMigrationTest : public ::testing::Test {
 protected:
  void SetUp() override {
    _sDbUrl = getDbUrl();
    if (_sDbUrl.empty()) {
      GTEST_SKIP() << "DNS_DB_URL not set — skipping integration test";
    }
    dns::common::Logger::init("warn");
    _cpPool = std::make_unique<dns::dal::ConnectionPool>(_sDbUrl, 2);
    _csService = std::make_unique<dns::security::CryptoService>(kTestMasterKey);
    _grRepo = std::make_unique<dns::dal::GitRepoRepository>(*_cpPool, *_csService);
    _vrRepo = std::make_unique<dns::dal::ViewRepository>(*_cpPool);
    _zrRepo = std::make_unique<dns::dal::ZoneRepository>(*_cpPool);

    // Clean test data
    {
      auto cg = _cpPool->checkout();
      pqxx::work txn(*cg);
      txn.exec("DELETE FROM records");
      txn.exec("DELETE FROM variables");
      txn.exec("DELETE FROM deployments");
      txn.exec("UPDATE zones SET git_repo_id = NULL");
      txn.exec("DELETE FROM zones");
      txn.exec("DELETE FROM git_repos");
      txn.exec("DELETE FROM view_providers");
      txn.exec("DELETE FROM views");
      txn.commit();
    }

    // Clear env vars
    unsetenv("DNS_GIT_REMOTE_URL");
    unsetenv("DNS_GIT_SSH_KEY_PATH");
    unsetenv("DNS_GIT_KNOWN_HOSTS_FILE");
    unsetenv("DNS_GIT_LOCAL_PATH");
  }

  void TearDown() override {
    unsetenv("DNS_GIT_REMOTE_URL");
    unsetenv("DNS_GIT_SSH_KEY_PATH");
    unsetenv("DNS_GIT_KNOWN_HOSTS_FILE");
    unsetenv("DNS_GIT_LOCAL_PATH");
  }

  std::string _sDbUrl;
  std::unique_ptr<dns::dal::ConnectionPool> _cpPool;
  std::unique_ptr<dns::security::CryptoService> _csService;
  std::unique_ptr<dns::dal::GitRepoRepository> _grRepo;
  std::unique_ptr<dns::dal::ViewRepository> _vrRepo;
  std::unique_ptr<dns::dal::ZoneRepository> _zrRepo;
};

TEST_F(GitOpsMigrationTest, ReturnsFalseWhenNoEnvVar) {
  EXPECT_FALSE(dns::gitops::GitOpsMigration::migrateIfNeeded(*_grRepo, *_zrRepo));
}

TEST_F(GitOpsMigrationTest, ReturnsFalseWhenGitReposExist) {
  _grRepo->create("existing", "https://gh.com/r.git", "none", "", "main", "", "");
  setenv("DNS_GIT_REMOTE_URL", "https://gh.com/other.git", 1);
  EXPECT_FALSE(dns::gitops::GitOpsMigration::migrateIfNeeded(*_grRepo, *_zrRepo));
}

TEST_F(GitOpsMigrationTest, MigratesEnvVarToGitRepos) {
  setenv("DNS_GIT_REMOTE_URL", "git@github.com:org/repo.git", 1);

  // Create a view and zone to verify assignment
  int64_t iViewId = _vrRepo->create("default", "Default view");
  int64_t iZoneId = _zrRepo->create("example.com", iViewId, std::nullopt);

  EXPECT_TRUE(dns::gitops::GitOpsMigration::migrateIfNeeded(*_grRepo, *_zrRepo));

  // Verify git_repos row was created
  auto vRepos = _grRepo->listAll();
  ASSERT_EQ(vRepos.size(), 1u);
  EXPECT_EQ(vRepos[0].sName, "default");
  EXPECT_EQ(vRepos[0].sRemoteUrl, "git@github.com:org/repo.git");

  // Verify zone was assigned to the repo
  auto oZone = _zrRepo->findById(iZoneId);
  ASSERT_TRUE(oZone.has_value());
  ASSERT_TRUE(oZone->oGitRepoId.has_value());
  EXPECT_EQ(*oZone->oGitRepoId, vRepos[0].iId);
}
