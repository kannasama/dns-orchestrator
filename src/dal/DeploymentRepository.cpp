#include "dal/DeploymentRepository.hpp"

#include "dal/ConnectionPool.hpp"

#include <pqxx/pqxx>

namespace dns::dal {

DeploymentRepository::DeploymentRepository(ConnectionPool& cpPool) : _cpPool(cpPool) {}
DeploymentRepository::~DeploymentRepository() = default;

int64_t DeploymentRepository::create(int64_t iZoneId, int64_t iDeployedByUserId,
                                     const nlohmann::json& jSnapshot) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);

  auto result = txn.exec(
      "INSERT INTO deployments (zone_id, deployed_by, seq, snapshot) "
      "VALUES ($1, $2, "
      "COALESCE((SELECT MAX(seq) FROM deployments WHERE zone_id = $1), 0) + 1, "
      "$3::jsonb) RETURNING id",
      pqxx::params{iZoneId, iDeployedByUserId, jSnapshot.dump()});
  txn.commit();
  return result.one_row()[0].as<int64_t>();
}

std::vector<DeploymentRow> DeploymentRepository::listByZoneId(int64_t iZoneId,
                                                              int iLimit) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT id, zone_id, deployed_by, "
      "EXTRACT(EPOCH FROM deployed_at)::bigint, seq, snapshot::text "
      "FROM deployments WHERE zone_id = $1 ORDER BY seq DESC LIMIT $2",
      pqxx::params{iZoneId, iLimit});
  txn.commit();

  std::vector<DeploymentRow> vRows;
  vRows.reserve(result.size());
  for (const auto& row : result) {
    DeploymentRow dr;
    dr.iId = row[0].as<int64_t>();
    dr.iZoneId = row[1].as<int64_t>();
    dr.iDeployedByUserId = row[2].as<int64_t>();
    dr.tpDeployedAt = std::chrono::system_clock::time_point(
        std::chrono::seconds(row[3].as<int64_t>()));
    dr.iSeq = row[4].as<int64_t>();
    dr.jSnapshot = nlohmann::json::parse(row[5].as<std::string>());
    vRows.push_back(std::move(dr));
  }
  return vRows;
}

std::optional<DeploymentRow> DeploymentRepository::findById(int64_t iId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT id, zone_id, deployed_by, "
      "EXTRACT(EPOCH FROM deployed_at)::bigint, seq, snapshot::text "
      "FROM deployments WHERE id = $1",
      pqxx::params{iId});
  txn.commit();

  if (result.empty()) return std::nullopt;

  DeploymentRow dr;
  dr.iId = result[0][0].as<int64_t>();
  dr.iZoneId = result[0][1].as<int64_t>();
  dr.iDeployedByUserId = result[0][2].as<int64_t>();
  dr.tpDeployedAt = std::chrono::system_clock::time_point(
      std::chrono::seconds(result[0][3].as<int64_t>()));
  dr.iSeq = result[0][4].as<int64_t>();
  dr.jSnapshot = nlohmann::json::parse(result[0][5].as<std::string>());
  return dr;
}

int DeploymentRepository::pruneByRetention(int64_t iZoneId, int iRetentionCount) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "DELETE FROM deployments WHERE zone_id = $1 AND seq <= "
      "(SELECT MAX(seq) - $2 FROM deployments WHERE zone_id = $1)",
      pqxx::params{iZoneId, iRetentionCount});
  txn.commit();
  return static_cast<int>(result.affected_rows());
}

}  // namespace dns::dal
