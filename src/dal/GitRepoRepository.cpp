#include "dal/GitRepoRepository.hpp"

#include <pqxx/pqxx>

#include "common/Errors.hpp"
#include "dal/ConnectionPool.hpp"
#include "security/CryptoService.hpp"

namespace dns::dal {

GitRepoRepository::GitRepoRepository(ConnectionPool& cpPool,
                                     const dns::security::CryptoService& csService)
    : _cpPool(cpPool), _csService(csService) {}

GitRepoRepository::~GitRepoRepository() = default;

GitRepoRow GitRepoRepository::mapRow(const pqxx::row& row, bool bDecryptCredentials) const {
  GitRepoRow gr;
  gr.iId = row["id"].as<int64_t>();
  gr.sName = row["name"].as<std::string>();
  gr.sRemoteUrl = row["remote_url"].as<std::string>();
  gr.sAuthType = row["auth_type"].as<std::string>();
  gr.sDefaultBranch = row["default_branch"].as<std::string>();
  gr.sLocalPath = row["local_path"].is_null() ? "" : row["local_path"].as<std::string>();
  gr.sKnownHosts = row["known_hosts"].is_null() ? "" : row["known_hosts"].as<std::string>();
  gr.bIsEnabled = row["is_enabled"].as<bool>();
  gr.sLastSyncAt = row["last_sync_at"].is_null() ? "" : row["last_sync_at"].as<std::string>();
  gr.sLastSyncStatus = row["last_sync_status"].is_null()
                           ? "" : row["last_sync_status"].as<std::string>();
  gr.sLastSyncError = row["last_sync_error"].is_null()
                          ? "" : row["last_sync_error"].as<std::string>();
  gr.sCreatedAt = row["created_at"].as<std::string>();
  gr.sUpdatedAt = row["updated_at"].as<std::string>();

  if (bDecryptCredentials && !row["encrypted_credentials"].is_null()) {
    std::string sEncrypted = row["encrypted_credentials"].as<std::string>();
    if (!sEncrypted.empty()) {
      gr.sDecryptedCredentials = _csService.decrypt(sEncrypted);
    }
  }

  return gr;
}

int64_t GitRepoRepository::create(const std::string& sName, const std::string& sRemoteUrl,
                                  const std::string& sAuthType,
                                  const std::string& sPlaintextCredentials,
                                  const std::string& sDefaultBranch,
                                  const std::string& sLocalPath,
                                  const std::string& sKnownHosts) {
  std::optional<std::string> oEncrypted;
  if (!sPlaintextCredentials.empty()) {
    oEncrypted = _csService.encrypt(sPlaintextCredentials);
  }

  std::optional<std::string> oLocalPath;
  if (!sLocalPath.empty()) oLocalPath = sLocalPath;

  std::optional<std::string> oKnownHosts;
  if (!sKnownHosts.empty()) oKnownHosts = sKnownHosts;

  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);

  auto result = txn.exec(
      "INSERT INTO git_repos (name, remote_url, auth_type, encrypted_credentials, "
      "default_branch, local_path, known_hosts) "
      "VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
      pqxx::params{sName, sRemoteUrl, sAuthType, oEncrypted,
                   sDefaultBranch, oLocalPath, oKnownHosts});

  txn.commit();
  return result[0][0].as<int64_t>();
}

std::vector<GitRepoRow> GitRepoRepository::listAll() {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec("SELECT * FROM git_repos ORDER BY name");
  txn.commit();

  std::vector<GitRepoRow> vRows;
  vRows.reserve(result.size());
  for (const auto& row : result) {
    vRows.push_back(mapRow(row, false));
  }
  return vRows;
}

std::vector<GitRepoRow> GitRepoRepository::listEnabled() {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT * FROM git_repos WHERE is_enabled = true ORDER BY name");
  txn.commit();

  std::vector<GitRepoRow> vRows;
  vRows.reserve(result.size());
  for (const auto& row : result) {
    vRows.push_back(mapRow(row, false));
  }
  return vRows;
}

std::optional<GitRepoRow> GitRepoRepository::findById(int64_t iId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec("SELECT * FROM git_repos WHERE id = $1", pqxx::params{iId});
  txn.commit();

  if (result.empty()) return std::nullopt;
  return mapRow(result[0], true);
}

std::optional<GitRepoRow> GitRepoRepository::findByName(const std::string& sName) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec("SELECT * FROM git_repos WHERE name = $1", pqxx::params{sName});
  txn.commit();

  if (result.empty()) return std::nullopt;
  return mapRow(result[0], true);
}

void GitRepoRepository::update(int64_t iId, const std::string& sName,
                               const std::string& sRemoteUrl, const std::string& sAuthType,
                               const std::string& sPlaintextCredentials,
                               const std::string& sDefaultBranch,
                               const std::string& sLocalPath,
                               const std::string& sKnownHosts,
                               bool bIsEnabled) {
  std::optional<std::string> oLocalPath;
  if (!sLocalPath.empty()) oLocalPath = sLocalPath;

  std::optional<std::string> oKnownHosts;
  if (!sKnownHosts.empty()) oKnownHosts = sKnownHosts;

  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);

  if (!sPlaintextCredentials.empty()) {
    std::string sEncrypted = _csService.encrypt(sPlaintextCredentials);
    txn.exec(
        "UPDATE git_repos SET name=$1, remote_url=$2, auth_type=$3, "
        "encrypted_credentials=$4, default_branch=$5, local_path=$6, "
        "known_hosts=$7, is_enabled=$8, updated_at=now() WHERE id=$9",
        pqxx::params{sName, sRemoteUrl, sAuthType, sEncrypted, sDefaultBranch,
                     oLocalPath, oKnownHosts, bIsEnabled, iId});
  } else {
    txn.exec(
        "UPDATE git_repos SET name=$1, remote_url=$2, auth_type=$3, "
        "default_branch=$4, local_path=$5, known_hosts=$6, is_enabled=$7, "
        "updated_at=now() WHERE id=$8",
        pqxx::params{sName, sRemoteUrl, sAuthType, sDefaultBranch,
                     oLocalPath, oKnownHosts, bIsEnabled, iId});
  }

  txn.commit();
}

void GitRepoRepository::updateSyncStatus(int64_t iId, const std::string& sStatus,
                                         const std::string& sError) {
  std::optional<std::string> oError;
  if (!sError.empty()) oError = sError;

  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  txn.exec(
      "UPDATE git_repos SET last_sync_at=now(), last_sync_status=$1, "
      "last_sync_error=$2 WHERE id=$3",
      pqxx::params{sStatus, oError, iId});
  txn.commit();
}

void GitRepoRepository::deleteById(int64_t iId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec("DELETE FROM git_repos WHERE id = $1 RETURNING id",
                         pqxx::params{iId});
  txn.commit();

  if (result.empty()) {
    throw dns::common::NotFoundError("GIT_REPO_NOT_FOUND",
                                     "Git repo " + std::to_string(iId) + " not found");
  }
}

}  // namespace dns::dal
