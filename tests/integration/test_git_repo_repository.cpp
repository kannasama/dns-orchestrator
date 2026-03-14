#include "dal/GitRepoRepository.hpp"

#include <gtest/gtest.h>
#include <cstdlib>
#include <pqxx/pqxx>

#include "common/Errors.hpp"
#include "common/Logger.hpp"
#include "dal/ConnectionPool.hpp"
#include "security/CryptoService.hpp"

namespace {
std::string getDbUrl() {
  const char* pUrl = std::getenv("DNS_DB_URL");
  return pUrl ? std::string(pUrl) : std::string{};
}
const std::string kTestMasterKey =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
}  // namespace

class GitRepoRepositoryTest : public ::testing::Test {
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

    auto cg = _cpPool->checkout();
    pqxx::work txn(*cg);
    txn.exec("UPDATE zones SET git_repo_id = NULL");
    txn.exec("DELETE FROM git_repos");
    txn.commit();
  }

  std::string _sDbUrl;
  std::unique_ptr<dns::dal::ConnectionPool> _cpPool;
  std::unique_ptr<dns::security::CryptoService> _csService;
  std::unique_ptr<dns::dal::GitRepoRepository> _grRepo;
};

TEST_F(GitRepoRepositoryTest, CreateAndFindById) {
  std::string sCreds = R"({"private_key":"test-key","passphrase":""})";
  int64_t iId = _grRepo->create("test-repo", "git@github.com:org/repo.git",
                                "ssh", sCreds, "main", "", "github.com ssh-rsa AAAA...");
  EXPECT_GT(iId, 0);

  auto oRow = _grRepo->findById(iId);
  ASSERT_TRUE(oRow.has_value());
  EXPECT_EQ(oRow->sName, "test-repo");
  EXPECT_EQ(oRow->sRemoteUrl, "git@github.com:org/repo.git");
  EXPECT_EQ(oRow->sAuthType, "ssh");
  EXPECT_EQ(oRow->sDecryptedCredentials, sCreds);
  EXPECT_EQ(oRow->sDefaultBranch, "main");
  EXPECT_TRUE(oRow->bIsEnabled);
}

TEST_F(GitRepoRepositoryTest, ListAllDoesNotDecryptCredentials) {
  _grRepo->create("repo-a", "https://github.com/org/a.git", "https",
                  R"({"username":"user","token":"ghp_xxx"})", "main", "", "");
  _grRepo->create("repo-b", "git@github.com:org/b.git", "ssh",
                  R"({"private_key":"key","passphrase":""})", "develop", "", "");

  auto vRows = _grRepo->listAll();
  ASSERT_EQ(vRows.size(), 2u);
  EXPECT_TRUE(vRows[0].sDecryptedCredentials.empty());
  EXPECT_TRUE(vRows[1].sDecryptedCredentials.empty());
  EXPECT_EQ(vRows[0].sName, "repo-a");
  EXPECT_EQ(vRows[1].sName, "repo-b");
}

TEST_F(GitRepoRepositoryTest, ListEnabled) {
  int64_t iId1 = _grRepo->create("enabled-repo", "https://gh.com/a.git",
                                  "none", "", "main", "", "");
  int64_t iId2 = _grRepo->create("disabled-repo", "https://gh.com/b.git",
                                  "none", "", "main", "", "");
  _grRepo->update(iId2, "disabled-repo", "https://gh.com/b.git", "none", "",
                  "main", "", "", false);

  auto vEnabled = _grRepo->listEnabled();
  ASSERT_EQ(vEnabled.size(), 1u);
  EXPECT_EQ(vEnabled[0].iId, iId1);
}

TEST_F(GitRepoRepositoryTest, UpdateWithNewCredentials) {
  int64_t iId = _grRepo->create("update-repo", "https://gh.com/repo.git",
                                "https", R"({"username":"u","token":"old"})",
                                "main", "", "");
  _grRepo->update(iId, "update-repo", "https://gh.com/repo.git", "https",
                  R"({"username":"u","token":"new"})", "develop", "", "", true);

  auto oRow = _grRepo->findById(iId);
  ASSERT_TRUE(oRow.has_value());
  EXPECT_EQ(oRow->sDecryptedCredentials, R"({"username":"u","token":"new"})");
  EXPECT_EQ(oRow->sDefaultBranch, "develop");
}

TEST_F(GitRepoRepositoryTest, UpdateWithoutChangingCredentials) {
  std::string sOrigCreds = R"({"private_key":"keep-me","passphrase":""})";
  int64_t iId = _grRepo->create("keep-creds-repo", "git@gh.com:x.git",
                                "ssh", sOrigCreds, "main", "", "");
  _grRepo->update(iId, "keep-creds-repo", "git@gh.com:x.git", "ssh",
                  "", "main", "", "", true);

  auto oRow = _grRepo->findById(iId);
  ASSERT_TRUE(oRow.has_value());
  EXPECT_EQ(oRow->sDecryptedCredentials, sOrigCreds);
}

TEST_F(GitRepoRepositoryTest, UpdateSyncStatus) {
  int64_t iId = _grRepo->create("sync-repo", "https://gh.com/s.git",
                                "none", "", "main", "", "");
  _grRepo->updateSyncStatus(iId, "success");

  auto oRow = _grRepo->findById(iId);
  ASSERT_TRUE(oRow.has_value());
  EXPECT_EQ(oRow->sLastSyncStatus, "success");
  EXPECT_FALSE(oRow->sLastSyncAt.empty());
  EXPECT_TRUE(oRow->sLastSyncError.empty());
}

TEST_F(GitRepoRepositoryTest, DeleteById) {
  int64_t iId = _grRepo->create("del-repo", "https://gh.com/d.git",
                                "none", "", "main", "", "");
  _grRepo->deleteById(iId);
  EXPECT_FALSE(_grRepo->findById(iId).has_value());
}

TEST_F(GitRepoRepositoryTest, DeleteNonExistentThrows) {
  EXPECT_THROW(_grRepo->deleteById(99999), dns::common::NotFoundError);
}

TEST_F(GitRepoRepositoryTest, FindByName) {
  _grRepo->create("named-repo", "https://gh.com/n.git", "none", "", "main", "", "");
  auto oRow = _grRepo->findByName("named-repo");
  ASSERT_TRUE(oRow.has_value());
  EXPECT_EQ(oRow->sRemoteUrl, "https://gh.com/n.git");
  EXPECT_FALSE(_grRepo->findByName("nonexistent").has_value());
}

TEST_F(GitRepoRepositoryTest, DuplicateNameThrows) {
  _grRepo->create("dup-repo", "https://gh.com/a.git", "none", "", "main", "", "");
  EXPECT_THROW(
      _grRepo->create("dup-repo", "https://gh.com/b.git", "none", "", "main", "", ""),
      std::exception);
}
