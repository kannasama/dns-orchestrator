#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace dns::dal {

class ConnectionPool;

/// Row type returned from view queries.
struct ViewRow {
  int64_t iId = 0;
  std::string sName;
  std::string sDescription;
  std::chrono::system_clock::time_point tpCreatedAt;
  std::vector<int64_t> vProviderIds;  // populated by findWithProviders()
};

/// Manages views + view_providers join table.
/// Class abbreviation: vr
class ViewRepository {
 public:
  explicit ViewRepository(ConnectionPool& cpPool);
  ~ViewRepository();

  /// Create a view. Returns the new ID.
  int64_t create(const std::string& sName, const std::string& sDescription);

  /// List all views (without provider IDs).
  std::vector<ViewRow> listAll();

  /// Find a view by ID (without provider IDs). Returns nullopt if not found.
  std::optional<ViewRow> findById(int64_t iId);

  /// Find a view by ID with provider IDs populated via JOIN.
  std::optional<ViewRow> findWithProviders(int64_t iId);

  /// Update a view's name and description. Throws NotFoundError if not found.
  void update(int64_t iId, const std::string& sName, const std::string& sDescription);

  /// Delete a view. Throws NotFoundError/ConflictError.
  void deleteById(int64_t iId);

  /// Attach a provider to a view (idempotent).
  void attachProvider(int64_t iViewId, int64_t iProviderId);

  /// Detach a provider from a view (idempotent).
  void detachProvider(int64_t iViewId, int64_t iProviderId);

 private:
  ConnectionPool& _cpPool;
};

}  // namespace dns::dal
