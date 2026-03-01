#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>

namespace dns::dal {

class ConnectionPool;

/// Row type returned from API key queries.
struct ApiKeyRow {
  int64_t iId = 0;
  int64_t iUserId = 0;
  std::string sKeyHash;
  std::string sDescription;
  bool bRevoked = false;
  std::optional<std::chrono::system_clock::time_point> oExpiresAt;
};

/// Manages the api_keys table; create, findByHash, scheduleDelete, pruneScheduled.
/// Class abbreviation: akr
class ApiKeyRepository {
 public:
  explicit ApiKeyRepository(ConnectionPool& cpPool);
  ~ApiKeyRepository();

  /// Create a new API key row. Returns the row ID.
  int64_t create(int64_t iUserId, const std::string& sKeyHash,
                 const std::string& sDescription,
                 std::optional<std::chrono::system_clock::time_point> oExpiresAt);

  /// Find an API key by its SHA-512 hash. Returns nullopt if not found.
  std::optional<ApiKeyRow> findByHash(const std::string& sKeyHash);

  /// Mark a key for deferred deletion: set delete_after = NOW() + grace seconds.
  void scheduleDelete(int64_t iKeyId, int iGraceSeconds);

  /// Delete all API key rows where delete_after < NOW(). Returns rows deleted.
  int pruneScheduled();

 private:
  ConnectionPool& _cpPool;
};

}  // namespace dns::dal
