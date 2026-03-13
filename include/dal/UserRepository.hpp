#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
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
  bool bForcePasswordChange = false;
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

  /// List all users.
  std::vector<UserRow> listAll();

  /// Update a user's email and active status.
  void update(int64_t iUserId, const std::string& sEmail, bool bIsActive);

  /// Deactivate a user (set is_active = false).
  void deactivate(int64_t iUserId);

  /// Update a user's password hash.
  void updatePassword(int64_t iUserId, const std::string& sPasswordHash);

  /// Set the force_password_change flag for a user.
  void setForcePasswordChange(int64_t iUserId, bool bForce);

  /// Add a user to a group with a specific role (and optional scope).
  void addToGroup(int64_t iUserId, int64_t iGroupId, int64_t iRoleId,
                  const std::string& sScopeType = "",
                  int64_t iScopeId = 0);

  /// Remove a user from a group (removes all role/scope memberships).
  void removeFromGroup(int64_t iUserId, int64_t iGroupId);

  /// List groups for a user as (group_id, group_name) pairs.
  std::vector<std::pair<int64_t, std::string>> listGroupsForUser(int64_t iUserId);

  /// Find a user by OIDC subject identifier. Returns nullopt if not found.
  std::optional<UserRow> findByOidcSub(const std::string& sOidcSub);

  /// Find a user by SAML NameID. Returns nullopt if not found.
  std::optional<UserRow> findBySamlNameId(const std::string& sSamlNameId);

  /// Create a federated user (no password hash). Returns the new user ID.
  int64_t createFederated(const std::string& sUsername, const std::string& sEmail,
                          const std::string& sAuthMethod,
                          const std::string& sOidcSub, const std::string& sSamlNameId);

  /// Update a federated user's email address.
  void updateFederatedEmail(int64_t iUserId, const std::string& sEmail);

 private:
  ConnectionPool& _cpPool;
};

}  // namespace dns::dal
