#include "dal/VariableRepository.hpp"

#include "common/Errors.hpp"
#include "dal/ConnectionPool.hpp"

#include <pqxx/pqxx>

namespace dns::dal {

VariableRepository::VariableRepository(ConnectionPool& cpPool) : _cpPool(cpPool) {}
VariableRepository::~VariableRepository() = default;

int64_t VariableRepository::create(const std::string& sName,
                                   const std::string& sValue,
                                   const std::string& sType,
                                   const std::string& sScope,
                                   std::optional<int64_t> oZoneId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  try {
    pqxx::result result;
    if (oZoneId.has_value()) {
      result = txn.exec(
          "INSERT INTO variables (name, value, type, scope, zone_id) "
          "VALUES ($1, $2, $3::variable_type, $4::variable_scope, $5) "
          "RETURNING id",
          pqxx::params{sName, sValue, sType, sScope, *oZoneId});
    } else {
      result = txn.exec(
          "INSERT INTO variables (name, value, type, scope) "
          "VALUES ($1, $2, $3::variable_type, $4::variable_scope) "
          "RETURNING id",
          pqxx::params{sName, sValue, sType, sScope});
    }
    txn.commit();
    return result.one_row()[0].as<int64_t>();
  } catch (const pqxx::unique_violation&) {
    throw common::ConflictError("duplicate_variable",
                                "Variable '" + sName + "' already exists in this scope");
  } catch (const pqxx::check_violation&) {
    throw common::ValidationError(
        "invalid_scope",
        "Global variables must not have a zone_id; zone variables require one");
  } catch (const pqxx::foreign_key_violation&) {
    throw common::NotFoundError("zone_not_found", "Zone not found");
  }
}

std::optional<VariableRow> VariableRepository::findById(int64_t iVariableId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT id, name, value, type::text, scope::text, zone_id, "
      "created_at::text, updated_at::text "
      "FROM variables WHERE id = $1",
      pqxx::params{iVariableId});
  txn.commit();

  if (result.empty()) return std::nullopt;

  auto row = result[0];
  VariableRow vRow;
  vRow.iId = row[0].as<int64_t>();
  vRow.sName = row[1].as<std::string>();
  vRow.sValue = row[2].as<std::string>();
  vRow.sType = row[3].as<std::string>();
  vRow.sScope = row[4].as<std::string>();
  if (!row[5].is_null()) {
    vRow.oZoneId = row[5].as<int64_t>();
  }
  vRow.sCreatedAt = row[6].as<std::string>();
  vRow.sUpdatedAt = row[7].as<std::string>();
  return vRow;
}

std::optional<VariableRow> VariableRepository::findByName(
    const std::string& sName, std::optional<int64_t> oZoneId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);

  pqxx::result result;
  if (oZoneId.has_value()) {
    result = txn.exec(
        "SELECT id, name, value, type::text, scope::text, zone_id, "
        "created_at::text, updated_at::text "
        "FROM variables WHERE name = $1 AND zone_id = $2",
        pqxx::params{sName, *oZoneId});
  } else {
    result = txn.exec(
        "SELECT id, name, value, type::text, scope::text, zone_id, "
        "created_at::text, updated_at::text "
        "FROM variables WHERE name = $1 AND zone_id IS NULL",
        pqxx::params{sName});
  }
  txn.commit();

  if (result.empty()) return std::nullopt;

  auto row = result[0];
  VariableRow vRow;
  vRow.iId = row[0].as<int64_t>();
  vRow.sName = row[1].as<std::string>();
  vRow.sValue = row[2].as<std::string>();
  vRow.sType = row[3].as<std::string>();
  vRow.sScope = row[4].as<std::string>();
  if (!row[5].is_null()) {
    vRow.oZoneId = row[5].as<int64_t>();
  }
  vRow.sCreatedAt = row[6].as<std::string>();
  vRow.sUpdatedAt = row[7].as<std::string>();
  return vRow;
}

std::vector<VariableRow> VariableRepository::list(
    std::optional<std::string> oScope, std::optional<int64_t> oZoneId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);

  pqxx::result result;
  if (oScope.has_value() && oZoneId.has_value()) {
    result = txn.exec(
        "SELECT id, name, value, type::text, scope::text, zone_id, "
        "created_at::text, updated_at::text "
        "FROM variables WHERE scope = $1::variable_scope AND zone_id = $2 "
        "ORDER BY name",
        pqxx::params{*oScope, *oZoneId});
  } else if (oScope.has_value()) {
    result = txn.exec(
        "SELECT id, name, value, type::text, scope::text, zone_id, "
        "created_at::text, updated_at::text "
        "FROM variables WHERE scope = $1::variable_scope ORDER BY name",
        pqxx::params{*oScope});
  } else if (oZoneId.has_value()) {
    result = txn.exec(
        "SELECT id, name, value, type::text, scope::text, zone_id, "
        "created_at::text, updated_at::text "
        "FROM variables WHERE zone_id = $1 ORDER BY name",
        pqxx::params{*oZoneId});
  } else {
    result = txn.exec(
        "SELECT id, name, value, type::text, scope::text, zone_id, "
        "created_at::text, updated_at::text "
        "FROM variables ORDER BY name");
  }
  txn.commit();

  std::vector<VariableRow> vRows;
  vRows.reserve(result.size());
  for (const auto& row : result) {
    VariableRow vRow;
    vRow.iId = row[0].as<int64_t>();
    vRow.sName = row[1].as<std::string>();
    vRow.sValue = row[2].as<std::string>();
    vRow.sType = row[3].as<std::string>();
    vRow.sScope = row[4].as<std::string>();
    if (!row[5].is_null()) {
      vRow.oZoneId = row[5].as<int64_t>();
    }
    vRow.sCreatedAt = row[6].as<std::string>();
    vRow.sUpdatedAt = row[7].as<std::string>();
    vRows.push_back(std::move(vRow));
  }
  return vRows;
}

void VariableRepository::update(int64_t iVariableId, const std::string& sName,
                                const std::string& sValue,
                                const std::string& sType) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  try {
    auto result = txn.exec(
        "UPDATE variables SET name = $2, value = $3, "
        "type = $4::variable_type, updated_at = NOW() "
        "WHERE id = $1",
        pqxx::params{iVariableId, sName, sValue, sType});
    txn.commit();
    if (result.affected_rows() == 0) {
      throw common::NotFoundError("variable_not_found", "Variable not found");
    }
  } catch (const pqxx::unique_violation&) {
    throw common::ConflictError("duplicate_variable",
                                "Variable '" + sName + "' already exists in this scope");
  }
}

void VariableRepository::deleteById(int64_t iVariableId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec("DELETE FROM variables WHERE id = $1",
                         pqxx::params{iVariableId});
  txn.commit();
  if (result.affected_rows() == 0) {
    throw common::NotFoundError("variable_not_found", "Variable not found");
  }
}

}  // namespace dns::dal
