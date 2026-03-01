#include "dal/ViewRepository.hpp"

#include "common/Errors.hpp"
#include "dal/ConnectionPool.hpp"

#include <pqxx/pqxx>

namespace dns::dal {

ViewRepository::ViewRepository(ConnectionPool& cpPool) : _cpPool(cpPool) {}
ViewRepository::~ViewRepository() = default;

std::vector<int64_t> ViewRepository::loadProviderIds(pqxx::work& txn,
                                                     int64_t iViewId) {
  auto result = txn.exec(
      "SELECT provider_id FROM view_providers "
      "WHERE view_id = $1 ORDER BY provider_id",
      pqxx::params{iViewId});
  std::vector<int64_t> vIds;
  vIds.reserve(result.size());
  for (const auto& row : result) {
    vIds.push_back(row[0].as<int64_t>());
  }
  return vIds;
}

int64_t ViewRepository::create(const std::string& sName,
                               const std::string& sDescription) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  try {
    std::optional<std::string> oDesc;
    if (!sDescription.empty()) oDesc = sDescription;
    auto result = txn.exec(
        "INSERT INTO views (name, description) VALUES ($1, $2) RETURNING id",
        pqxx::params{sName, oDesc});
    txn.commit();
    return result.one_row()[0].as<int64_t>();
  } catch (const pqxx::unique_violation&) {
    throw common::ConflictError("duplicate_view",
                                "View with name '" + sName + "' already exists");
  }
}

std::optional<ViewRow> ViewRepository::findById(int64_t iViewId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT id, name, COALESCE(description, ''), created_at::text "
      "FROM views WHERE id = $1",
      pqxx::params{iViewId});

  if (result.empty()) {
    txn.commit();
    return std::nullopt;
  }

  auto row = result[0];
  ViewRow vRow;
  vRow.iId = row[0].as<int64_t>();
  vRow.sName = row[1].as<std::string>();
  vRow.sDescription = row[2].as<std::string>();
  vRow.sCreatedAt = row[3].as<std::string>();
  vRow.vProviderIds = loadProviderIds(txn, iViewId);
  txn.commit();
  return vRow;
}

std::vector<ViewRow> ViewRepository::list() {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT id, name, COALESCE(description, ''), created_at::text "
      "FROM views ORDER BY name");

  std::vector<ViewRow> vRows;
  vRows.reserve(result.size());
  for (const auto& row : result) {
    ViewRow vRow;
    vRow.iId = row[0].as<int64_t>();
    vRow.sName = row[1].as<std::string>();
    vRow.sDescription = row[2].as<std::string>();
    vRow.sCreatedAt = row[3].as<std::string>();
    vRow.vProviderIds = loadProviderIds(txn, vRow.iId);
    vRows.push_back(std::move(vRow));
  }
  txn.commit();
  return vRows;
}

void ViewRepository::update(int64_t iViewId, const std::string& sName,
                            const std::string& sDescription) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  try {
    std::optional<std::string> oDesc;
    if (!sDescription.empty()) oDesc = sDescription;
    auto result = txn.exec(
        "UPDATE views SET name = $2, description = $3 WHERE id = $1",
        pqxx::params{iViewId, sName, oDesc});
    txn.commit();
    if (result.affected_rows() == 0) {
      throw common::NotFoundError("view_not_found", "View not found");
    }
  } catch (const pqxx::unique_violation&) {
    throw common::ConflictError("duplicate_view",
                                "View with name '" + sName + "' already exists");
  }
}

void ViewRepository::deleteById(int64_t iViewId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec("DELETE FROM views WHERE id = $1",
                         pqxx::params{iViewId});
  txn.commit();
  if (result.affected_rows() == 0) {
    throw common::NotFoundError("view_not_found", "View not found");
  }
}

void ViewRepository::attachProvider(int64_t iViewId, int64_t iProviderId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  try {
    txn.exec(
        "INSERT INTO view_providers (view_id, provider_id) VALUES ($1, $2)",
        pqxx::params{iViewId, iProviderId});
    txn.commit();
  } catch (const pqxx::unique_violation&) {
    throw common::ConflictError(
        "provider_already_attached",
        "Provider is already attached to this view");
  } catch (const pqxx::foreign_key_violation& e) {
    std::string sMsg = e.what();
    if (sMsg.find("view_providers_view_id_fkey") != std::string::npos) {
      throw common::NotFoundError("view_not_found", "View not found");
    }
    throw common::NotFoundError("provider_not_found", "Provider not found");
  }
}

void ViewRepository::detachProvider(int64_t iViewId, int64_t iProviderId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "DELETE FROM view_providers WHERE view_id = $1 AND provider_id = $2",
      pqxx::params{iViewId, iProviderId});
  txn.commit();
  if (result.affected_rows() == 0) {
    throw common::NotFoundError("provider_not_attached",
                                "Provider is not attached to this view");
  }
}

}  // namespace dns::dal
