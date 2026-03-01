#include "dal/DeploymentRepository.hpp"

#include "common/Errors.hpp"
#include "dal/ConnectionPool.hpp"

#include <pqxx/pqxx>

namespace dns::dal {

DeploymentRepository::DeploymentRepository(ConnectionPool& cpPool)
    : _cpPool(cpPool) {}
DeploymentRepository::~DeploymentRepository() = default;

int64_t DeploymentRepository::create(int64_t iZoneId, int64_t iDeployedBy,
                                     const std::string& sSnapshotJson) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  // Assign next seq atomically within the transaction
  auto seqResult = txn.exec(
      "SELECT COALESCE(MAX(seq), 0) + 1 FROM deployments WHERE zone_id = $1",
      pqxx::params{iZoneId});
  int64_t iNextSeq = seqResult.one_row()[0].as<int64_t>();

  auto result = txn.exec(
      "INSERT INTO deployments (zone_id, deployed_by, seq, snapshot) "
      "VALUES ($1, $2, $3, $4::jsonb) RETURNING id",
      pqxx::params{iZoneId, iDeployedBy, iNextSeq, sSnapshotJson});
  txn.commit();
  return result.one_row()[0].as<int64_t>();
}

std::optional<DeploymentRow> DeploymentRepository::findById(
    int64_t iDeploymentId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT id, zone_id, deployed_by, deployed_at::text, seq, "
      "snapshot::text "
      "FROM deployments WHERE id = $1",
      pqxx::params{iDeploymentId});
  txn.commit();

  if (result.empty()) return std::nullopt;

  auto row = result[0];
  return DeploymentRow{
      row[0].as<int64_t>(),
      row[1].as<int64_t>(),
      row[2].as<int64_t>(),
      row[3].as<std::string>(),
      row[4].as<int64_t>(),
      row[5].as<std::string>(),
  };
}

std::vector<DeploymentRow> DeploymentRepository::listByZone(int64_t iZoneId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT id, zone_id, deployed_by, deployed_at::text, seq, "
      "snapshot::text "
      "FROM deployments WHERE zone_id = $1 ORDER BY seq DESC",
      pqxx::params{iZoneId});
  txn.commit();

  std::vector<DeploymentRow> vRows;
  vRows.reserve(result.size());
  for (const auto& row : result) {
    vRows.push_back({
        row[0].as<int64_t>(),
        row[1].as<int64_t>(),
        row[2].as<int64_t>(),
        row[3].as<std::string>(),
        row[4].as<int64_t>(),
        row[5].as<std::string>(),
    });
  }
  return vRows;
}

int DeploymentRepository::pruneOldSnapshots(int64_t iZoneId,
                                            int iRetentionCount) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  // Delete all deployments for this zone except the N most recent (by seq).
  auto result = txn.exec(
      "DELETE FROM deployments WHERE zone_id = $1 AND id NOT IN ("
      "  SELECT id FROM deployments WHERE zone_id = $1 "
      "  ORDER BY seq DESC LIMIT $2"
      ")",
      pqxx::params{iZoneId, iRetentionCount});
  txn.commit();
  return static_cast<int>(result.affected_rows());
}

}  // namespace dns::dal
