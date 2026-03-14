#include "gitops/GitRepoManager.hpp"

#include <gtest/gtest.h>
#include <cstdlib>
#include <filesystem>
#include <pqxx/pqxx>

#include "common/Logger.hpp"
#include "core/VariableEngine.hpp"
#include "dal/ConnectionPool.hpp"
#include "dal/GitRepoRepository.hpp"
#include "dal/RecordRepository.hpp"
#include "dal/VariableRepository.hpp"
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

class GitRepoManagerTest : public ::testing::Test {
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
    _rrRepo = std::make_unique<dns::dal::RecordRepository>(*_cpPool);
    _varRepo = std::make_unique<dns::dal::VariableRepository>(*_cpPool);
    _veEngine = std::make_unique<dns::core::VariableEngine>(*_varRepo);

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

    _sTmpDir = std::filesystem::temp_directory_path() / "grmgr-test";
    std::filesystem::remove_all(_sTmpDir);
    std::filesystem::create_directories(_sTmpDir);
  }

  void TearDown() override {
    std::filesystem::remove_all(_sTmpDir);
  }

  std::string _sDbUrl;
  std::filesystem::path _sTmpDir;
  std::unique_ptr<dns::dal::ConnectionPool> _cpPool;
  std::unique_ptr<dns::security::CryptoService> _csService;
  std::unique_ptr<dns::dal::GitRepoRepository> _grRepo;
  std::unique_ptr<dns::dal::ViewRepository> _vrRepo;
  std::unique_ptr<dns::dal::ZoneRepository> _zrRepo;
  std::unique_ptr<dns::dal::RecordRepository> _rrRepo;
  std::unique_ptr<dns::dal::VariableRepository> _varRepo;
  std::unique_ptr<dns::core::VariableEngine> _veEngine;
};

TEST_F(GitRepoManagerTest, InitializeWithNoRepos) {
  dns::gitops::GitRepoManager mgr(*_grRepo, *_zrRepo, *_vrRepo, *_rrRepo,
                                   *_veEngine, _sTmpDir.string());
  EXPECT_NO_THROW(mgr.initialize());
}

TEST_F(GitRepoManagerTest, CommitZoneSnapshotNoOpWhenNoGitRepoAssigned) {
  int64_t iViewId = _vrRepo->create("test-view", "Test view");
  int64_t iZoneId = _zrRepo->create("example.com", iViewId, std::nullopt);

  dns::gitops::GitRepoManager mgr(*_grRepo, *_zrRepo, *_vrRepo, *_rrRepo,
                                   *_veEngine, _sTmpDir.string());
  mgr.initialize();

  // Should be a no-op since zone has no git_repo_id
  EXPECT_NO_THROW(mgr.commitZoneSnapshot(iZoneId, "test-user"));
}

TEST_F(GitRepoManagerTest, RemoveRepoUnloadsMirror) {
  // Create a local-only repo
  auto sRepoDir = _sTmpDir / "local-repo";
  std::system(("git init " + sRepoDir.string() + " 2>/dev/null").c_str());

  int64_t iRepoId = _grRepo->create("test-repo", "", "none", "",
                                      "main", sRepoDir.string(), "");

  dns::gitops::GitRepoManager mgr(*_grRepo, *_zrRepo, *_vrRepo, *_rrRepo,
                                   *_veEngine, _sTmpDir.string());
  mgr.initialize();

  // Remove should succeed without error
  EXPECT_NO_THROW(mgr.removeRepo(iRepoId));
  // Removing again should also be fine (idempotent)
  EXPECT_NO_THROW(mgr.removeRepo(iRepoId));
}
