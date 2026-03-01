#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <pqxx/pqxx>

namespace dns::dal {

class ConnectionPool;

/// Row type returned from view queries.
struct ViewRow {
  int64_t iId = 0;
  std::string sName;
  std::string sDescription;
  std::string sCreatedAt;
  std::vector<int64_t> vProviderIds;
};

/// Manages views + view_providers join table.
/// Class abbreviation: vr
class ViewRepository {
 public:
  explicit ViewRepository(ConnectionPool& cpPool);
  ~ViewRepository();

  /// Create a view. Returns the new view ID.
  /// Throws ConflictError if name already exists.
  int64_t create(const std::string& sName, const std::string& sDescription);

  /// Find a view by ID (includes attached provider IDs).
  /// Returns nullopt if not found.
  std::optional<ViewRow> findById(int64_t iViewId);

  /// List all views (includes attached provider IDs for each).
  std::vector<ViewRow> list();

  /// Update a view's name and description.
  /// Throws NotFoundError if view doesn't exist.
  void update(int64_t iViewId, const std::string& sName,
              const std::string& sDescription);

  /// Delete a view by ID.
  /// Throws NotFoundError if view doesn't exist.
  void deleteById(int64_t iViewId);

  /// Attach a provider to a view.
  /// Throws ConflictError if already attached.
  void attachProvider(int64_t iViewId, int64_t iProviderId);

  /// Detach a provider from a view.
  /// Throws NotFoundError if not attached.
  void detachProvider(int64_t iViewId, int64_t iProviderId);

 private:
  /// Load provider IDs for a given view within an existing transaction.
  std::vector<int64_t> loadProviderIds(pqxx::work& txn, int64_t iViewId);

  ConnectionPool& _cpPool;
};

}  // namespace dns::dal
