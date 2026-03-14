#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace dns::dal {

class ConnectionPool;

/// Row type returned from zone queries.
struct ZoneRow {
  int64_t iId = 0;
  std::string sName;
  int64_t iViewId = 0;
  std::optional<int> oDeploymentRetention;
  bool bManageSoa = false;
  bool bManageNs = false;
  std::string sSyncStatus;  // "unknown", "in_sync", "drift", "error"
  std::optional<std::chrono::system_clock::time_point> oSyncCheckedAt;
  std::optional<int64_t> oGitRepoId;      // FK to git_repos
  std::optional<std::string> oGitBranch;   // Branch override (nullopt = use repo default)
  std::chrono::system_clock::time_point tpCreatedAt;
};

/// Manages the zones table.
/// Class abbreviation: zr
class ZoneRepository {
 public:
  explicit ZoneRepository(ConnectionPool& cpPool);
  ~ZoneRepository();

  /// Create a zone. Returns the new ID.
  int64_t create(const std::string& sName, int64_t iViewId,
                 std::optional<int> oRetention,
                 bool bManageSoa = false, bool bManageNs = false,
                 std::optional<int64_t> oGitRepoId = std::nullopt,
                 std::optional<std::string> oGitBranch = std::nullopt);

  /// List all zones.
  std::vector<ZoneRow> listAll();

  /// List zones belonging to a view.
  std::vector<ZoneRow> listByViewId(int64_t iViewId);

  /// Find a zone by ID. Returns nullopt if not found.
  std::optional<ZoneRow> findById(int64_t iId);

  /// Update a zone's name, view, and retention.
  void update(int64_t iId, const std::string& sName, int64_t iViewId,
              std::optional<int> oRetention, bool bManageSoa = false,
              bool bManageNs = false,
              std::optional<int64_t> oGitRepoId = std::nullopt,
              std::optional<std::string> oGitBranch = std::nullopt);

  /// Update a zone's sync status and set sync_checked_at to NOW().
  void updateSyncStatus(int64_t iZoneId, const std::string& sSyncStatus);

  /// Delete a zone. Cascades to records, variables, deployments.
  void deleteById(int64_t iId);

 private:
  ConnectionPool& _cpPool;
};

}  // namespace dns::dal
