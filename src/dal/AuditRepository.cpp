#include "dal/AuditRepository.hpp"

#include "dal/ConnectionPool.hpp"

#include <pqxx/pqxx>
#include <sstream>

namespace dns::dal {

AuditRepository::AuditRepository(ConnectionPool& cpPool) : _cpPool(cpPool) {}
AuditRepository::~AuditRepository() = default;

int64_t AuditRepository::insert(const std::string& sEntityType,
                                std::optional<int64_t> oEntityId,
                                const std::string& sOperation,
                                const std::optional<nlohmann::json>& ojOldValue,
                                const std::optional<nlohmann::json>& ojNewValue,
                                const std::string& sIdentity,
                                const std::optional<std::string>& osAuthMethod,
                                const std::optional<std::string>& osIpAddress) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);

  // Build nullable parameters
  std::optional<int64_t> entityId = oEntityId;
  std::optional<std::string> oldVal =
      ojOldValue.has_value() ? std::optional(ojOldValue->dump()) : std::nullopt;
  std::optional<std::string> newVal =
      ojNewValue.has_value() ? std::optional(ojNewValue->dump()) : std::nullopt;

  pqxx::result result;
  if (osAuthMethod.has_value()) {
    result = txn.exec(
        "INSERT INTO audit_log (entity_type, entity_id, operation, old_value, new_value, "
        "identity, auth_method, ip_address) "
        "VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6, $7::auth_method, $8::inet) "
        "RETURNING id",
        pqxx::params{sEntityType, entityId, sOperation, oldVal, newVal,
                     sIdentity, *osAuthMethod, osIpAddress});
  } else {
    result = txn.exec(
        "INSERT INTO audit_log (entity_type, entity_id, operation, old_value, new_value, "
        "identity, ip_address) "
        "VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6, $7::inet) "
        "RETURNING id",
        pqxx::params{sEntityType, entityId, sOperation, oldVal, newVal,
                     sIdentity, osIpAddress});
  }

  txn.commit();
  return result.one_row()[0].as<int64_t>();
}

std::vector<AuditLogRow> AuditRepository::query(
    const std::optional<std::string>& osEntityType,
    const std::optional<int64_t>& oEntityId,
    const std::optional<std::string>& osIdentity,
    const std::optional<std::chrono::system_clock::time_point>& otpFrom,
    const std::optional<std::chrono::system_clock::time_point>& otpTo,
    int iLimit) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);

  // Build dynamic query with parameterised placeholders
  std::ostringstream sql;
  sql << "SELECT id, entity_type, entity_id, operation, "
         "old_value::text, new_value::text, variable_used, "
         "identity, auth_method::text, ip_address::text, "
         "EXTRACT(EPOCH FROM timestamp)::bigint "
         "FROM audit_log WHERE 1=1";

  // Collect parameters
  std::vector<std::string> vConditions;
  pqxx::params params;
  int iParamIdx = 1;

  if (osEntityType.has_value()) {
    sql << " AND entity_type = $" << iParamIdx++;
    params.append(*osEntityType);
  }
  if (oEntityId.has_value()) {
    sql << " AND entity_id = $" << iParamIdx++;
    params.append(*oEntityId);
  }
  if (osIdentity.has_value()) {
    sql << " AND identity = $" << iParamIdx++;
    params.append(*osIdentity);
  }
  if (otpFrom.has_value()) {
    auto iEpoch = std::chrono::duration_cast<std::chrono::seconds>(
                      otpFrom->time_since_epoch())
                      .count();
    sql << " AND timestamp >= to_timestamp($" << iParamIdx++ << ")";
    params.append(iEpoch);
  }
  if (otpTo.has_value()) {
    auto iEpoch = std::chrono::duration_cast<std::chrono::seconds>(
                      otpTo->time_since_epoch())
                      .count();
    sql << " AND timestamp <= to_timestamp($" << iParamIdx++ << ")";
    params.append(iEpoch);
  }

  sql << " ORDER BY timestamp DESC LIMIT $" << iParamIdx;
  params.append(iLimit);

  auto result = txn.exec(sql.str(), params);
  txn.commit();

  std::vector<AuditLogRow> vRows;
  vRows.reserve(result.size());
  for (const auto& row : result) {
    AuditLogRow ar;
    ar.iId = row[0].as<int64_t>();
    ar.sEntityType = row[1].as<std::string>();
    if (!row[2].is_null()) ar.oEntityId = row[2].as<int64_t>();
    ar.sOperation = row[3].as<std::string>();
    if (!row[4].is_null()) ar.ojOldValue = nlohmann::json::parse(row[4].as<std::string>());
    if (!row[5].is_null()) ar.ojNewValue = nlohmann::json::parse(row[5].as<std::string>());
    if (!row[6].is_null()) ar.osVariableUsed = row[6].as<std::string>();
    ar.sIdentity = row[7].as<std::string>();
    if (!row[8].is_null()) ar.osAuthMethod = row[8].as<std::string>();
    if (!row[9].is_null()) ar.osIpAddress = row[9].as<std::string>();
    ar.tpTimestamp = std::chrono::system_clock::time_point(
        std::chrono::seconds(row[10].as<int64_t>()));
    vRows.push_back(std::move(ar));
  }
  return vRows;
}

PurgeResult AuditRepository::purgeOld(int iRetentionDays) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);

  auto delResult = txn.exec(
      "DELETE FROM audit_log WHERE timestamp < NOW() - make_interval(days => $1)",
      pqxx::params{iRetentionDays});
  int64_t iDeleted = static_cast<int64_t>(delResult.affected_rows());

  PurgeResult pr;
  pr.iDeletedCount = iDeleted;

  auto oldestResult = txn.exec(
      "SELECT EXTRACT(EPOCH FROM MIN(timestamp))::bigint FROM audit_log");
  if (!oldestResult.empty() && !oldestResult[0][0].is_null()) {
    pr.oOldestRemaining = std::chrono::system_clock::time_point(
        std::chrono::seconds(oldestResult[0][0].as<int64_t>()));
  }

  // Record the purge operation itself
  if (iDeleted > 0) {
    nlohmann::json jNew = {{"deleted_count", iDeleted},
                           {"retention_days", iRetentionDays}};
    txn.exec(
        "INSERT INTO audit_log (entity_type, operation, new_value, identity) "
        "VALUES ('audit_log', 'purge', $1::jsonb, 'system')",
        pqxx::params{jNew.dump()});
  }

  txn.commit();
  return pr;
}

}  // namespace dns::dal
