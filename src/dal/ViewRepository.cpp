#include "dal/ViewRepository.hpp"

#include "common/Errors.hpp"
#include "dal/ConnectionPool.hpp"

#include <pqxx/pqxx>

namespace dns::dal {

ViewRepository::ViewRepository(ConnectionPool& cpPool) : _cpPool(cpPool) {}
ViewRepository::~ViewRepository() = default;

int64_t ViewRepository::create(const std::string& sName, const std::string& sDescription) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);

  try {
    auto result = txn.exec(
        "INSERT INTO views (name, description) VALUES ($1, $2) RETURNING id",
        pqxx::params{sName, sDescription});
    txn.commit();
    return result.one_row()[0].as<int64_t>();
  } catch (const pqxx::unique_violation&) {
    throw common::ConflictError("VIEW_EXISTS",
                                "View with name '" + sName + "' already exists");
  }
}

std::vector<ViewRow> ViewRepository::listAll() {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT id, name, COALESCE(description, ''), "
      "EXTRACT(EPOCH FROM created_at)::bigint "
      "FROM views ORDER BY id");
  txn.commit();

  std::vector<ViewRow> vRows;
  vRows.reserve(result.size());
  for (const auto& row : result) {
    ViewRow vr;
    vr.iId = row[0].as<int64_t>();
    vr.sName = row[1].as<std::string>();
    vr.sDescription = row[2].as<std::string>();
    vr.tpCreatedAt = std::chrono::system_clock::time_point(
        std::chrono::seconds(row[3].as<int64_t>()));
    vRows.push_back(std::move(vr));
  }
  return vRows;
}

std::optional<ViewRow> ViewRepository::findById(int64_t iId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT id, name, COALESCE(description, ''), "
      "EXTRACT(EPOCH FROM created_at)::bigint "
      "FROM views WHERE id = $1",
      pqxx::params{iId});
  txn.commit();

  if (result.empty()) return std::nullopt;

  ViewRow vr;
  vr.iId = result[0][0].as<int64_t>();
  vr.sName = result[0][1].as<std::string>();
  vr.sDescription = result[0][2].as<std::string>();
  vr.tpCreatedAt = std::chrono::system_clock::time_point(
      std::chrono::seconds(result[0][3].as<int64_t>()));
  return vr;
}

std::optional<ViewRow> ViewRepository::findWithProviders(int64_t iId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);

  auto viewResult = txn.exec(
      "SELECT id, name, COALESCE(description, ''), "
      "EXTRACT(EPOCH FROM created_at)::bigint "
      "FROM views WHERE id = $1",
      pqxx::params{iId});

  if (viewResult.empty()) {
    txn.commit();
    return std::nullopt;
  }

  ViewRow vr;
  vr.iId = viewResult[0][0].as<int64_t>();
  vr.sName = viewResult[0][1].as<std::string>();
  vr.sDescription = viewResult[0][2].as<std::string>();
  vr.tpCreatedAt = std::chrono::system_clock::time_point(
      std::chrono::seconds(viewResult[0][3].as<int64_t>()));

  auto provResult = txn.exec(
      "SELECT provider_id FROM view_providers WHERE view_id = $1 ORDER BY provider_id",
      pqxx::params{iId});
  txn.commit();

  for (const auto& row : provResult) {
    vr.vProviderIds.push_back(row[0].as<int64_t>());
  }
  return vr;
}

void ViewRepository::update(int64_t iId, const std::string& sName,
                            const std::string& sDescription) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);

  pqxx::result result;
  try {
    result = txn.exec(
        "UPDATE views SET name = $2, description = $3 WHERE id = $1",
        pqxx::params{iId, sName, sDescription});
    txn.commit();
  } catch (const pqxx::unique_violation&) {
    throw common::ConflictError("VIEW_EXISTS",
                                "View with name '" + sName + "' already exists");
  }

  if (result.affected_rows() == 0) {
    throw common::NotFoundError("VIEW_NOT_FOUND",
                                "View with id " + std::to_string(iId) + " not found");
  }
}

void ViewRepository::deleteById(int64_t iId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);

  try {
    auto result = txn.exec("DELETE FROM views WHERE id = $1", pqxx::params{iId});
    txn.commit();

    if (result.affected_rows() == 0) {
      throw common::NotFoundError("VIEW_NOT_FOUND",
                                  "View with id " + std::to_string(iId) + " not found");
    }
  } catch (const pqxx::foreign_key_violation&) {
    throw common::ConflictError("VIEW_HAS_ZONES",
                                "Cannot delete view — zones still reference it");
  }
}

void ViewRepository::attachProvider(int64_t iViewId, int64_t iProviderId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);

  try {
    txn.exec(
        "INSERT INTO view_providers (view_id, provider_id) VALUES ($1, $2) "
        "ON CONFLICT DO NOTHING",
        pqxx::params{iViewId, iProviderId});
    txn.commit();
  } catch (const pqxx::foreign_key_violation&) {
    throw common::NotFoundError("INVALID_VIEW_OR_PROVIDER",
                                "View or provider does not exist");
  }
}

void ViewRepository::detachProvider(int64_t iViewId, int64_t iProviderId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  txn.exec(
      "DELETE FROM view_providers WHERE view_id = $1 AND provider_id = $2",
      pqxx::params{iViewId, iProviderId});
  txn.commit();
}

}  // namespace dns::dal
