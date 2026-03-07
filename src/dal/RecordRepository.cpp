#include "dal/RecordRepository.hpp"

#include "common/Errors.hpp"
#include "dal/ConnectionPool.hpp"

#include <pqxx/pqxx>

namespace dns::dal {

RecordRepository::RecordRepository(ConnectionPool& cpPool) : _cpPool(cpPool) {}
RecordRepository::~RecordRepository() = default;

int64_t RecordRepository::create(int64_t iZoneId, const std::string& sName,
                                 const std::string& sType, int iTtl,
                                 const std::string& sValueTemplate, int iPriority) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);

  try {
    auto result = txn.exec(
        "INSERT INTO records (zone_id, name, type, ttl, value_template, priority) "
        "VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
        pqxx::params{iZoneId, sName, sType, iTtl, sValueTemplate, iPriority});
    txn.commit();
    return result.one_row()[0].as<int64_t>();
  } catch (const pqxx::foreign_key_violation&) {
    throw common::ValidationError("INVALID_ZONE_ID",
                                  "Zone with id " + std::to_string(iZoneId) + " not found");
  }
}

std::vector<RecordRow> RecordRepository::listByZoneId(int64_t iZoneId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT id, zone_id, name, type, ttl, value_template, priority, last_audit_id, "
      "EXTRACT(EPOCH FROM created_at)::bigint, "
      "EXTRACT(EPOCH FROM updated_at)::bigint "
      "FROM records WHERE zone_id = $1 ORDER BY id",
      pqxx::params{iZoneId});
  txn.commit();

  std::vector<RecordRow> vRows;
  vRows.reserve(result.size());
  for (const auto& row : result) {
    RecordRow rr;
    rr.iId = row[0].as<int64_t>();
    rr.iZoneId = row[1].as<int64_t>();
    rr.sName = row[2].as<std::string>();
    rr.sType = row[3].as<std::string>();
    rr.iTtl = row[4].as<int>();
    rr.sValueTemplate = row[5].as<std::string>();
    rr.iPriority = row[6].as<int>();
    if (!row[7].is_null()) rr.oLastAuditId = row[7].as<int64_t>();
    rr.tpCreatedAt = std::chrono::system_clock::time_point(
        std::chrono::seconds(row[8].as<int64_t>()));
    rr.tpUpdatedAt = std::chrono::system_clock::time_point(
        std::chrono::seconds(row[9].as<int64_t>()));
    vRows.push_back(std::move(rr));
  }
  return vRows;
}

std::optional<RecordRow> RecordRepository::findById(int64_t iId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT id, zone_id, name, type, ttl, value_template, priority, last_audit_id, "
      "EXTRACT(EPOCH FROM created_at)::bigint, "
      "EXTRACT(EPOCH FROM updated_at)::bigint "
      "FROM records WHERE id = $1",
      pqxx::params{iId});
  txn.commit();

  if (result.empty()) return std::nullopt;

  RecordRow rr;
  rr.iId = result[0][0].as<int64_t>();
  rr.iZoneId = result[0][1].as<int64_t>();
  rr.sName = result[0][2].as<std::string>();
  rr.sType = result[0][3].as<std::string>();
  rr.iTtl = result[0][4].as<int>();
  rr.sValueTemplate = result[0][5].as<std::string>();
  rr.iPriority = result[0][6].as<int>();
  if (!result[0][7].is_null()) rr.oLastAuditId = result[0][7].as<int64_t>();
  rr.tpCreatedAt = std::chrono::system_clock::time_point(
      std::chrono::seconds(result[0][8].as<int64_t>()));
  rr.tpUpdatedAt = std::chrono::system_clock::time_point(
      std::chrono::seconds(result[0][9].as<int64_t>()));
  return rr;
}

void RecordRepository::update(int64_t iId, const std::string& sName,
                              const std::string& sType, int iTtl,
                              const std::string& sValueTemplate, int iPriority) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "UPDATE records SET name = $2, type = $3, ttl = $4, value_template = $5, "
      "priority = $6, updated_at = NOW() WHERE id = $1",
      pqxx::params{iId, sName, sType, iTtl, sValueTemplate, iPriority});
  txn.commit();

  if (result.affected_rows() == 0) {
    throw common::NotFoundError("RECORD_NOT_FOUND",
                                "Record with id " + std::to_string(iId) + " not found");
  }
}

void RecordRepository::deleteById(int64_t iId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec("DELETE FROM records WHERE id = $1", pqxx::params{iId});
  txn.commit();

  if (result.affected_rows() == 0) {
    throw common::NotFoundError("RECORD_NOT_FOUND",
                                "Record with id " + std::to_string(iId) + " not found");
  }
}

int RecordRepository::deleteAllByZoneId(int64_t iZoneId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec("DELETE FROM records WHERE zone_id = $1",
                         pqxx::params{iZoneId});
  txn.commit();
  return static_cast<int>(result.affected_rows());
}

int64_t RecordRepository::upsertById(int64_t iId, int64_t iZoneId,
                                     const std::string& sName, const std::string& sType,
                                     int iTtl, const std::string& sValueTemplate,
                                     int iPriority) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);

  // Try update first
  auto result = txn.exec(
      "UPDATE records SET name = $2, type = $3, ttl = $4, value_template = $5, "
      "priority = $6, updated_at = NOW() WHERE id = $1 RETURNING id",
      pqxx::params{iId, sName, sType, iTtl, sValueTemplate, iPriority});

  if (!result.empty()) {
    txn.commit();
    return result[0][0].as<int64_t>();
  }

  // Record doesn't exist — insert new one
  result = txn.exec(
      "INSERT INTO records (zone_id, name, type, ttl, value_template, priority) "
      "VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
      pqxx::params{iZoneId, sName, sType, iTtl, sValueTemplate, iPriority});
  txn.commit();
  return result.one_row()[0].as<int64_t>();
}

std::vector<int64_t> RecordRepository::createBatch(
    int64_t iZoneId,
    const std::vector<std::tuple<std::string, std::string, int, std::string, int>>& vRecords) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);

  std::vector<int64_t> vIds;
  vIds.reserve(vRecords.size());

  try {
    for (const auto& [sName, sType, iTtl, sValueTemplate, iPriority] : vRecords) {
      auto result = txn.exec(
          "INSERT INTO records (zone_id, name, type, ttl, value_template, priority) "
          "VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
          pqxx::params{iZoneId, sName, sType, iTtl, sValueTemplate, iPriority});
      vIds.push_back(result.one_row()[0].as<int64_t>());
    }
    txn.commit();
  } catch (const pqxx::foreign_key_violation&) {
    throw common::ValidationError("INVALID_ZONE_ID",
                                  "Zone with id " + std::to_string(iZoneId) + " not found");
  }
  return vIds;
}

}  // namespace dns::dal
