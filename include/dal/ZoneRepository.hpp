#pragma once

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
  std::string sCreatedAt;
};

/// Manages the zones table.
/// Class abbreviation: zr
class ZoneRepository {
 public:
  explicit ZoneRepository(ConnectionPool& cpPool);
  ~ZoneRepository();

  /// Create a zone. Returns the new zone ID.
  /// Throws ConflictError if (name, view_id) already exists.
  int64_t create(const std::string& sName, int64_t iViewId,
                 std::optional<int> oDeploymentRetention);

  /// Find a zone by ID. Returns nullopt if not found.
  std::optional<ZoneRow> findById(int64_t iZoneId);

  /// List zones, optionally filtered by view_id.
  std::vector<ZoneRow> list(std::optional<int64_t> oViewId);

  /// Update a zone.
  /// Throws NotFoundError if zone doesn't exist.
  void update(int64_t iZoneId, const std::string& sName, int64_t iViewId,
              std::optional<int> oDeploymentRetention);

  /// Delete a zone by ID.
  /// Throws NotFoundError if zone doesn't exist.
  void deleteById(int64_t iZoneId);

 private:
  ConnectionPool& _cpPool;
};

}  // namespace dns::dal
