#include "dal/ZoneRepository.hpp"

#include "common/Errors.hpp"
#include "dal/ConnectionPool.hpp"

#include <pqxx/pqxx>

namespace dns::dal {

ZoneRepository::ZoneRepository(ConnectionPool& cpPool) : _cpPool(cpPool) {}
ZoneRepository::~ZoneRepository() = default;

int64_t ZoneRepository::create(const std::string& sName, int64_t iViewId,
                               std::optional<int> oDeploymentRetention) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  try {
    pqxx::result result;
    if (oDeploymentRetention.has_value()) {
      result = txn.exec(
          "INSERT INTO zones (name, view_id, deployment_retention) "
          "VALUES ($1, $2, $3) RETURNING id",
          pqxx::params{sName, iViewId, *oDeploymentRetention});
    } else {
      result = txn.exec(
          "INSERT INTO zones (name, view_id) VALUES ($1, $2) RETURNING id",
          pqxx::params{sName, iViewId});
    }
    txn.commit();
    return result.one_row()[0].as<int64_t>();
  } catch (const pqxx::unique_violation&) {
    throw common::ConflictError(
        "duplicate_zone",
        "Zone '" + sName + "' already exists in this view");
  } catch (const pqxx::foreign_key_violation&) {
    throw common::NotFoundError("view_not_found", "View not found");
  }
}

std::optional<ZoneRow> ZoneRepository::findById(int64_t iZoneId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT id, name, view_id, deployment_retention, created_at::text "
      "FROM zones WHERE id = $1",
      pqxx::params{iZoneId});
  txn.commit();

  if (result.empty()) return std::nullopt;

  auto row = result[0];
  ZoneRow zRow;
  zRow.iId = row[0].as<int64_t>();
  zRow.sName = row[1].as<std::string>();
  zRow.iViewId = row[2].as<int64_t>();
  if (!row[3].is_null()) {
    zRow.oDeploymentRetention = row[3].as<int>();
  }
  zRow.sCreatedAt = row[4].as<std::string>();
  return zRow;
}

std::vector<ZoneRow> ZoneRepository::list(std::optional<int64_t> oViewId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);

  pqxx::result result;
  if (oViewId.has_value()) {
    result = txn.exec(
        "SELECT id, name, view_id, deployment_retention, created_at::text "
        "FROM zones WHERE view_id = $1 ORDER BY name",
        pqxx::params{*oViewId});
  } else {
    result = txn.exec(
        "SELECT id, name, view_id, deployment_retention, created_at::text "
        "FROM zones ORDER BY name");
  }
  txn.commit();

  std::vector<ZoneRow> vRows;
  vRows.reserve(result.size());
  for (const auto& row : result) {
    ZoneRow zRow;
    zRow.iId = row[0].as<int64_t>();
    zRow.sName = row[1].as<std::string>();
    zRow.iViewId = row[2].as<int64_t>();
    if (!row[3].is_null()) {
      zRow.oDeploymentRetention = row[3].as<int>();
    }
    zRow.sCreatedAt = row[4].as<std::string>();
    vRows.push_back(std::move(zRow));
  }
  return vRows;
}

void ZoneRepository::update(int64_t iZoneId, const std::string& sName,
                            int64_t iViewId,
                            std::optional<int> oDeploymentRetention) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  try {
    pqxx::result result;
    if (oDeploymentRetention.has_value()) {
      result = txn.exec(
          "UPDATE zones SET name = $2, view_id = $3, deployment_retention = $4 "
          "WHERE id = $1",
          pqxx::params{iZoneId, sName, iViewId, *oDeploymentRetention});
    } else {
      result = txn.exec(
          "UPDATE zones SET name = $2, view_id = $3, deployment_retention = NULL "
          "WHERE id = $1",
          pqxx::params{iZoneId, sName, iViewId});
    }
    txn.commit();
    if (result.affected_rows() == 0) {
      throw common::NotFoundError("zone_not_found", "Zone not found");
    }
  } catch (const pqxx::unique_violation&) {
    throw common::ConflictError(
        "duplicate_zone",
        "Zone '" + sName + "' already exists in this view");
  } catch (const pqxx::foreign_key_violation&) {
    throw common::NotFoundError("view_not_found", "View not found");
  }
}

void ZoneRepository::deleteById(int64_t iZoneId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec("DELETE FROM zones WHERE id = $1",
                         pqxx::params{iZoneId});
  txn.commit();
  if (result.affected_rows() == 0) {
    throw common::NotFoundError("zone_not_found", "Zone not found");
  }
}

}  // namespace dns::dal
