#include "dal/VariableRepository.hpp"

#include "common/Errors.hpp"
#include "dal/ConnectionPool.hpp"

#include <pqxx/pqxx>

namespace dns::dal {

VariableRepository::VariableRepository(ConnectionPool& cpPool) : _cpPool(cpPool) {}
VariableRepository::~VariableRepository() = default;

int64_t VariableRepository::create(const std::string& sName, const std::string& sValue,
                                   const std::string& sType, const std::string& sScope,
                                   std::optional<int64_t> oZoneId) {
  // Validate scope/zone_id consistency before touching the database.
  if (sScope == "global" && oZoneId.has_value()) {
    throw common::ValidationError("SCOPE_ZONE_MISMATCH",
                                  "scope='global' requires zone_id to be NULL");
  }
  if (sScope == "zone" && !oZoneId.has_value()) {
    throw common::ValidationError("SCOPE_ZONE_MISMATCH",
                                  "scope='zone' requires a zone_id");
  }

  // PostgreSQL UNIQUE(name, zone_id) treats NULL as distinct, so enforce
  // global uniqueness in application logic.
  if (sScope == "global") {
    auto cg = _cpPool.checkout();
    pqxx::work txn(*cg);
    auto existing = txn.exec(
        "SELECT id FROM variables WHERE name = $1 AND zone_id IS NULL",
        pqxx::params{sName});
    if (!existing.empty()) {
      txn.commit();
      throw common::ConflictError("VARIABLE_EXISTS",
                                  "Global variable '" + sName + "' already exists");
    }

    try {
      auto result = txn.exec(
          "INSERT INTO variables (name, value, type, scope) "
          "VALUES ($1, $2, $3::variable_type, $4::variable_scope) RETURNING id",
          pqxx::params{sName, sValue, sType, sScope});
      txn.commit();
      return result.one_row()[0].as<int64_t>();
    } catch (const pqxx::check_violation&) {
      throw common::ValidationError("SCOPE_ZONE_MISMATCH",
                                    "scope='global' requires zone_id to be NULL");
    }
  }

  // Zone-scoped variable
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);

  try {
    auto result = txn.exec(
        "INSERT INTO variables (name, value, type, scope, zone_id) "
        "VALUES ($1, $2, $3::variable_type, $4::variable_scope, $5) RETURNING id",
        pqxx::params{sName, sValue, sType, sScope, *oZoneId});
    txn.commit();
    return result.one_row()[0].as<int64_t>();
  } catch (const pqxx::unique_violation&) {
    throw common::ConflictError("VARIABLE_EXISTS",
                                "Variable '" + sName + "' already exists in this zone");
  } catch (const pqxx::check_violation&) {
    throw common::ValidationError("SCOPE_ZONE_MISMATCH",
                                  "scope/zone_id mismatch: scope='zone' requires zone_id");
  } catch (const pqxx::foreign_key_violation&) {
    throw common::ValidationError("INVALID_ZONE_ID",
                                  "Zone with id " + std::to_string(*oZoneId) + " not found");
  }
}

namespace {

VariableRow mapVariableRow(const pqxx::row& row) {
  VariableRow vr;
  vr.iId = row[0].as<int64_t>();
  vr.sName = row[1].as<std::string>();
  vr.sValue = row[2].as<std::string>();
  vr.sType = row[3].as<std::string>();
  vr.sScope = row[4].as<std::string>();
  if (!row[5].is_null()) vr.oZoneId = row[5].as<int64_t>();
  vr.tpCreatedAt = std::chrono::system_clock::time_point(
      std::chrono::seconds(row[6].as<int64_t>()));
  vr.tpUpdatedAt = std::chrono::system_clock::time_point(
      std::chrono::seconds(row[7].as<int64_t>()));
  return vr;
}

const char* kSelectVariables =
    "SELECT id, name, value, type::text, scope::text, zone_id, "
    "EXTRACT(EPOCH FROM created_at)::bigint, "
    "EXTRACT(EPOCH FROM updated_at)::bigint "
    "FROM variables";

}  // namespace

std::vector<VariableRow> VariableRepository::listAll() {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(std::string(kSelectVariables) + " ORDER BY id");
  txn.commit();

  std::vector<VariableRow> vRows;
  vRows.reserve(result.size());
  for (const auto& row : result) {
    vRows.push_back(mapVariableRow(row));
  }
  return vRows;
}

std::vector<VariableRow> VariableRepository::listByScope(const std::string& sScope) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      std::string(kSelectVariables) + " WHERE scope = $1::variable_scope ORDER BY id",
      pqxx::params{sScope});
  txn.commit();

  std::vector<VariableRow> vRows;
  vRows.reserve(result.size());
  for (const auto& row : result) {
    vRows.push_back(mapVariableRow(row));
  }
  return vRows;
}

std::vector<VariableRow> VariableRepository::listByZoneId(int64_t iZoneId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      std::string(kSelectVariables) +
          " WHERE zone_id = $1 OR scope = 'global' ORDER BY id",
      pqxx::params{iZoneId});
  txn.commit();

  std::vector<VariableRow> vRows;
  vRows.reserve(result.size());
  for (const auto& row : result) {
    vRows.push_back(mapVariableRow(row));
  }
  return vRows;
}

std::optional<VariableRow> VariableRepository::findById(int64_t iId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      std::string(kSelectVariables) + " WHERE id = $1",
      pqxx::params{iId});
  txn.commit();

  if (result.empty()) return std::nullopt;
  return mapVariableRow(result[0]);
}

void VariableRepository::update(int64_t iId, const std::string& sValue) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "UPDATE variables SET value = $2, updated_at = NOW() WHERE id = $1",
      pqxx::params{iId, sValue});
  txn.commit();

  if (result.affected_rows() == 0) {
    throw common::NotFoundError("VARIABLE_NOT_FOUND",
                                "Variable with id " + std::to_string(iId) + " not found");
  }
}

void VariableRepository::deleteById(int64_t iId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec("DELETE FROM variables WHERE id = $1", pqxx::params{iId});
  txn.commit();

  if (result.affected_rows() == 0) {
    throw common::NotFoundError("VARIABLE_NOT_FOUND",
                                "Variable with id " + std::to_string(iId) + " not found");
  }
}

}  // namespace dns::dal
