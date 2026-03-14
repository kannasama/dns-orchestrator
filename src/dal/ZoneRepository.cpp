#include "dal/ZoneRepository.hpp"

#include "common/Errors.hpp"
#include "dal/ConnectionPool.hpp"

#include <pqxx/pqxx>

namespace dns::dal {

ZoneRepository::ZoneRepository(ConnectionPool& cpPool) : _cpPool(cpPool) {}
ZoneRepository::~ZoneRepository() = default;

int64_t ZoneRepository::create(const std::string& sName, int64_t iViewId,
                               std::optional<int> oRetention,
                               bool bManageSoa, bool bManageNs,
                               std::optional<int64_t> oGitRepoId,
                               std::optional<std::string> oGitBranch) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);

  try {
    pqxx::result result;
    if (oRetention.has_value()) {
      result = txn.exec(
          "INSERT INTO zones (name, view_id, deployment_retention, manage_soa, manage_ns, "
          "git_repo_id, git_branch) "
          "VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
          pqxx::params{sName, iViewId, *oRetention, bManageSoa, bManageNs,
                       oGitRepoId, oGitBranch});
    } else {
      result = txn.exec(
          "INSERT INTO zones (name, view_id, manage_soa, manage_ns, "
          "git_repo_id, git_branch) "
          "VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
          pqxx::params{sName, iViewId, bManageSoa, bManageNs,
                       oGitRepoId, oGitBranch});
    }
    txn.commit();
    return result.one_row()[0].as<int64_t>();
  } catch (const pqxx::unique_violation&) {
    throw common::ConflictError("ZONE_EXISTS",
                                "Zone '" + sName + "' already exists in this view");
  } catch (const pqxx::foreign_key_violation&) {
    throw common::ValidationError("INVALID_VIEW_ID",
                                  "View with id " + std::to_string(iViewId) + " not found");
  }
}

std::vector<ZoneRow> ZoneRepository::listAll() {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT id, name, view_id, deployment_retention, manage_soa, manage_ns, "
      "EXTRACT(EPOCH FROM created_at)::bigint, "
      "sync_status, EXTRACT(EPOCH FROM sync_checked_at)::bigint, "
      "git_repo_id, git_branch "
      "FROM zones ORDER BY id");
  txn.commit();

  std::vector<ZoneRow> vRows;
  vRows.reserve(result.size());
  for (const auto& row : result) {
    ZoneRow zr;
    zr.iId = row[0].as<int64_t>();
    zr.sName = row[1].as<std::string>();
    zr.iViewId = row[2].as<int64_t>();
    if (!row[3].is_null()) zr.oDeploymentRetention = row[3].as<int>();
    zr.bManageSoa = row[4].as<bool>();
    zr.bManageNs = row[5].as<bool>();
    zr.tpCreatedAt = std::chrono::system_clock::time_point(
        std::chrono::seconds(row[6].as<int64_t>()));
    zr.sSyncStatus = row[7].as<std::string>();
    if (!row[8].is_null()) {
      zr.oSyncCheckedAt = std::chrono::system_clock::time_point(
          std::chrono::seconds(row[8].as<int64_t>()));
    }
    if (!row[9].is_null()) zr.oGitRepoId = row[9].as<int64_t>();
    if (!row[10].is_null()) zr.oGitBranch = row[10].as<std::string>();
    vRows.push_back(std::move(zr));
  }
  return vRows;
}

std::vector<ZoneRow> ZoneRepository::listByViewId(int64_t iViewId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT id, name, view_id, deployment_retention, manage_soa, manage_ns, "
      "EXTRACT(EPOCH FROM created_at)::bigint, "
      "sync_status, EXTRACT(EPOCH FROM sync_checked_at)::bigint, "
      "git_repo_id, git_branch "
      "FROM zones WHERE view_id = $1 ORDER BY id",
      pqxx::params{iViewId});
  txn.commit();

  std::vector<ZoneRow> vRows;
  vRows.reserve(result.size());
  for (const auto& row : result) {
    ZoneRow zr;
    zr.iId = row[0].as<int64_t>();
    zr.sName = row[1].as<std::string>();
    zr.iViewId = row[2].as<int64_t>();
    if (!row[3].is_null()) zr.oDeploymentRetention = row[3].as<int>();
    zr.bManageSoa = row[4].as<bool>();
    zr.bManageNs = row[5].as<bool>();
    zr.tpCreatedAt = std::chrono::system_clock::time_point(
        std::chrono::seconds(row[6].as<int64_t>()));
    zr.sSyncStatus = row[7].as<std::string>();
    if (!row[8].is_null()) {
      zr.oSyncCheckedAt = std::chrono::system_clock::time_point(
          std::chrono::seconds(row[8].as<int64_t>()));
    }
    if (!row[9].is_null()) zr.oGitRepoId = row[9].as<int64_t>();
    if (!row[10].is_null()) zr.oGitBranch = row[10].as<std::string>();
    vRows.push_back(std::move(zr));
  }
  return vRows;
}

std::optional<ZoneRow> ZoneRepository::findById(int64_t iId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT id, name, view_id, deployment_retention, manage_soa, manage_ns, "
      "EXTRACT(EPOCH FROM created_at)::bigint, "
      "sync_status, EXTRACT(EPOCH FROM sync_checked_at)::bigint, "
      "git_repo_id, git_branch "
      "FROM zones WHERE id = $1",
      pqxx::params{iId});
  txn.commit();

  if (result.empty()) return std::nullopt;

  ZoneRow zr;
  zr.iId = result[0][0].as<int64_t>();
  zr.sName = result[0][1].as<std::string>();
  zr.iViewId = result[0][2].as<int64_t>();
  if (!result[0][3].is_null()) zr.oDeploymentRetention = result[0][3].as<int>();
  zr.bManageSoa = result[0][4].as<bool>();
  zr.bManageNs = result[0][5].as<bool>();
  zr.tpCreatedAt = std::chrono::system_clock::time_point(
      std::chrono::seconds(result[0][6].as<int64_t>()));
  zr.sSyncStatus = result[0][7].as<std::string>();
  if (!result[0][8].is_null()) {
    zr.oSyncCheckedAt = std::chrono::system_clock::time_point(
        std::chrono::seconds(result[0][8].as<int64_t>()));
  }
  if (!result[0][9].is_null()) zr.oGitRepoId = result[0][9].as<int64_t>();
  if (!result[0][10].is_null()) zr.oGitBranch = result[0][10].as<std::string>();
  return zr;
}

void ZoneRepository::update(int64_t iId, const std::string& sName, int64_t iViewId,
                            std::optional<int> oRetention,
                            bool bManageSoa, bool bManageNs,
                            std::optional<int64_t> oGitRepoId,
                            std::optional<std::string> oGitBranch) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);

  pqxx::result result;
  try {
    if (oRetention.has_value()) {
      result = txn.exec(
          "UPDATE zones SET name = $2, view_id = $3, deployment_retention = $4, "
          "manage_soa = $5, manage_ns = $6, git_repo_id = $7, git_branch = $8 "
          "WHERE id = $1",
          pqxx::params{iId, sName, iViewId, *oRetention, bManageSoa, bManageNs,
                       oGitRepoId, oGitBranch});
    } else {
      result = txn.exec(
          "UPDATE zones SET name = $2, view_id = $3, deployment_retention = NULL, "
          "manage_soa = $4, manage_ns = $5, git_repo_id = $6, git_branch = $7 "
          "WHERE id = $1",
          pqxx::params{iId, sName, iViewId, bManageSoa, bManageNs,
                       oGitRepoId, oGitBranch});
    }
    txn.commit();
  } catch (const pqxx::unique_violation&) {
    throw common::ConflictError("ZONE_EXISTS",
                                "Zone '" + sName + "' already exists in this view");
  }

  if (result.affected_rows() == 0) {
    throw common::NotFoundError("ZONE_NOT_FOUND",
                                "Zone with id " + std::to_string(iId) + " not found");
  }
}

void ZoneRepository::updateSyncStatus(int64_t iZoneId, const std::string& sSyncStatus) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  txn.exec(
      "UPDATE zones SET sync_status = $1, sync_checked_at = NOW() WHERE id = $2",
      pqxx::params{sSyncStatus, iZoneId});
  txn.commit();
}

void ZoneRepository::deleteById(int64_t iId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec("DELETE FROM zones WHERE id = $1", pqxx::params{iId});
  txn.commit();

  if (result.affected_rows() == 0) {
    throw common::NotFoundError("ZONE_NOT_FOUND",
                                "Zone with id " + std::to_string(iId) + " not found");
  }
}

}  // namespace dns::dal
