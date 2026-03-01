#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace dns::dal {

class ConnectionPool;

/// Row type returned from user queries.
struct UserRow {
  int64_t iId = 0;
  std::string sUsername;
  std::string sEmail;
  std::string sPasswordHash;
  std::string sAuthMethod;
  bool bIsActive = true;
};

/// Manages users + groups + group_members.
/// Class abbreviation: ur
class UserRepository {
 public:
  explicit UserRepository(ConnectionPool& cpPool);
  ~UserRepository();

  /// Find a user by username. Returns nullopt if not found.
  std::optional<UserRow> findByUsername(const std::string& sUsername);

  /// Find a user by ID. Returns nullopt if not found.
  std::optional<UserRow> findById(int64_t iUserId);

  /// Create a local user. Returns the new user ID.
  int64_t create(const std::string& sUsername, const std::string& sEmail,
                 const std::string& sPasswordHash);

  /// Resolve the highest-privilege role for a user across all their groups.
  /// Returns "admin", "operator", or "viewer". Returns empty string if user
  /// has no group membership.
  std::string getHighestRole(int64_t iUserId);

 private:
  ConnectionPool& _cpPool;
};

}  // namespace dns::dal
