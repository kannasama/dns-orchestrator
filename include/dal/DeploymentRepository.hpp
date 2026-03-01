#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace dns::dal {

class ConnectionPool;

/// Row type returned from deployment queries.
struct DeploymentRow {
  int64_t iId = 0;
  int64_t iZoneId = 0;
  int64_t iDeployedBy = 0;
  std::string sDeployedAt;
  int64_t iSeq = 0;
  std::string sSnapshot;  // raw JSONB string
};

/// Manages the deployments table; snapshot create, get, list, prune.
/// Class abbreviation: dr
class DeploymentRepository {
 public:
  explicit DeploymentRepository(ConnectionPool& cpPool);
  ~DeploymentRepository();

  /// Create a deployment snapshot. Auto-assigns next seq for the zone.
  /// Returns the new deployment ID.
  int64_t create(int64_t iZoneId, int64_t iDeployedBy,
                 const std::string& sSnapshotJson);

  /// Find a deployment by ID. Returns nullopt if not found.
  std::optional<DeploymentRow> findById(int64_t iDeploymentId);

  /// List deployments for a zone, ordered by seq DESC (newest first).
  std::vector<DeploymentRow> listByZone(int64_t iZoneId);

  /// Prune old snapshots beyond retention count for a zone.
  /// Keeps the most recent iRetentionCount deployments.
  /// Returns the number of deleted snapshots.
  int pruneOldSnapshots(int64_t iZoneId, int iRetentionCount);

 private:
  ConnectionPool& _cpPool;
};

}  // namespace dns::dal
