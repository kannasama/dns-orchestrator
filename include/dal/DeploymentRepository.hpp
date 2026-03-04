#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace dns::dal {

class ConnectionPool;

/// Row type returned from deployment queries.
struct DeploymentRow {
  int64_t iId = 0;
  int64_t iZoneId = 0;
  int64_t iDeployedByUserId = 0;
  std::chrono::system_clock::time_point tpDeployedAt;
  int64_t iSeq = 0;
  nlohmann::json jSnapshot;
};

/// Manages the deployments table; snapshot create, get, list, prune.
/// Class abbreviation: dr
class DeploymentRepository {
 public:
  explicit DeploymentRepository(ConnectionPool& cpPool);
  ~DeploymentRepository();

  /// Create a deployment snapshot. Auto-generates seq. Returns the new ID.
  int64_t create(int64_t iZoneId, int64_t iDeployedByUserId,
                 const nlohmann::json& jSnapshot);

  /// List deployments for a zone, ordered by seq DESC with LIMIT.
  std::vector<DeploymentRow> listByZoneId(int64_t iZoneId, int iLimit = 50);

  /// Find a deployment by ID. Returns nullopt if not found.
  std::optional<DeploymentRow> findById(int64_t iId);

  /// Keep the N most recent deployments, delete the rest. Returns deleted count.
  int pruneByRetention(int64_t iZoneId, int iRetentionCount);

 private:
  ConnectionPool& _cpPool;
};

}  // namespace dns::dal
