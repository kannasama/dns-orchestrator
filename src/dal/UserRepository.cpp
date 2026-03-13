#include "dal/UserRepository.hpp"

#include "common/Errors.hpp"
#include "dal/ConnectionPool.hpp"

#include <pqxx/pqxx>

namespace dns::dal {

UserRepository::UserRepository(ConnectionPool& cpPool) : _cpPool(cpPool) {}
UserRepository::~UserRepository() = default;

std::optional<UserRow> UserRepository::findByUsername(const std::string& sUsername) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT id, username, COALESCE(email, ''), COALESCE(password_hash, ''), "
      "auth_method::text, is_active, COALESCE(force_password_change, false) "
      "FROM users WHERE username = $1",
      pqxx::params{sUsername});
  txn.commit();

  if (result.empty()) return std::nullopt;

  auto row = result[0];
  return UserRow{
      row[0].as<int64_t>(),
      row[1].as<std::string>(),
      row[2].as<std::string>(),
      row[3].as<std::string>(),
      row[4].as<std::string>(),
      row[5].as<bool>(),
      row[6].as<bool>(),
  };
}

std::optional<UserRow> UserRepository::findById(int64_t iUserId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT id, username, COALESCE(email, ''), COALESCE(password_hash, ''), "
      "auth_method::text, is_active, COALESCE(force_password_change, false) "
      "FROM users WHERE id = $1",
      pqxx::params{iUserId});
  txn.commit();

  if (result.empty()) return std::nullopt;

  auto row = result[0];
  return UserRow{
      row[0].as<int64_t>(),
      row[1].as<std::string>(),
      row[2].as<std::string>(),
      row[3].as<std::string>(),
      row[4].as<std::string>(),
      row[5].as<bool>(),
      row[6].as<bool>(),
  };
}

int64_t UserRepository::create(const std::string& sUsername, const std::string& sEmail,
                               const std::string& sPasswordHash) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "INSERT INTO users (username, email, password_hash, auth_method) "
      "VALUES ($1, $2, $3, 'local') RETURNING id",
      pqxx::params{sUsername, sEmail, sPasswordHash});
  txn.commit();
  return result.one_row()[0].as<int64_t>();
}

std::vector<UserRow> UserRepository::listAll() {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT id, username, COALESCE(email, ''), COALESCE(password_hash, ''), "
      "auth_method::text, is_active, COALESCE(force_password_change, false) "
      "FROM users ORDER BY username");
  txn.commit();

  std::vector<UserRow> vRows;
  vRows.reserve(result.size());
  for (const auto& row : result) {
    UserRow ur;
    ur.iId = row[0].as<int64_t>();
    ur.sUsername = row[1].as<std::string>();
    ur.sEmail = row[2].as<std::string>();
    ur.sPasswordHash = row[3].as<std::string>();
    ur.sAuthMethod = row[4].as<std::string>();
    ur.bIsActive = row[5].as<bool>();
    ur.bForcePasswordChange = row[6].as<bool>();
    vRows.push_back(std::move(ur));
  }
  return vRows;
}

void UserRepository::update(int64_t iUserId, const std::string& sEmail, bool bIsActive) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "UPDATE users SET email = $2, is_active = $3, updated_at = NOW() WHERE id = $1",
      pqxx::params{iUserId, sEmail, bIsActive});
  txn.commit();

  if (result.affected_rows() == 0) {
    throw common::NotFoundError("USER_NOT_FOUND",
                                "User with id " + std::to_string(iUserId) + " not found");
  }
}

void UserRepository::deactivate(int64_t iUserId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "UPDATE users SET is_active = false, updated_at = NOW() WHERE id = $1",
      pqxx::params{iUserId});
  txn.commit();

  if (result.affected_rows() == 0) {
    throw common::NotFoundError("USER_NOT_FOUND",
                                "User with id " + std::to_string(iUserId) + " not found");
  }
}

void UserRepository::updatePassword(int64_t iUserId, const std::string& sPasswordHash) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "UPDATE users SET password_hash = $2, force_password_change = false, "
      "updated_at = NOW() WHERE id = $1",
      pqxx::params{iUserId, sPasswordHash});
  txn.commit();

  if (result.affected_rows() == 0) {
    throw common::NotFoundError("USER_NOT_FOUND",
                                "User with id " + std::to_string(iUserId) + " not found");
  }
}

void UserRepository::setForcePasswordChange(int64_t iUserId, bool bForce) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "UPDATE users SET force_password_change = $2, updated_at = NOW() WHERE id = $1",
      pqxx::params{iUserId, bForce});
  txn.commit();

  if (result.affected_rows() == 0) {
    throw common::NotFoundError("USER_NOT_FOUND",
                                "User with id " + std::to_string(iUserId) + " not found");
  }
}

void UserRepository::addToGroup(int64_t iUserId, int64_t iGroupId, int64_t iRoleId,
                                const std::string& sScopeType, int64_t iScopeId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);

  try {
    if (sScopeType.empty()) {
      txn.exec(
          "INSERT INTO group_members (user_id, group_id, role_id) VALUES ($1, $2, $3) "
          "ON CONFLICT DO NOTHING",
          pqxx::params{iUserId, iGroupId, iRoleId});
    } else {
      txn.exec(
          "INSERT INTO group_members (user_id, group_id, role_id, scope_type, scope_id) "
          "VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
          pqxx::params{iUserId, iGroupId, iRoleId, sScopeType, iScopeId});
    }
    txn.commit();
  } catch (const pqxx::foreign_key_violation&) {
    throw common::NotFoundError("INVALID_USER_OR_GROUP",
                                "User, group, or role does not exist");
  }
}

void UserRepository::removeFromGroup(int64_t iUserId, int64_t iGroupId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  txn.exec(
      "DELETE FROM group_members WHERE user_id = $1 AND group_id = $2",
      pqxx::params{iUserId, iGroupId});
  txn.commit();
}

std::vector<std::pair<int64_t, std::string>> UserRepository::listGroupsForUser(int64_t iUserId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT g.id, g.name FROM groups g "
      "JOIN group_members gm ON gm.group_id = g.id "
      "WHERE gm.user_id = $1 "
      "ORDER BY g.name",
      pqxx::params{iUserId});
  txn.commit();

  std::vector<std::pair<int64_t, std::string>> vGroups;
  vGroups.reserve(result.size());
  for (const auto& row : result) {
    vGroups.emplace_back(row[0].as<int64_t>(), row[1].as<std::string>());
  }
  return vGroups;
}

std::optional<UserRow> UserRepository::findByOidcSub(const std::string& sOidcSub) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT id, username, COALESCE(email, ''), COALESCE(password_hash, ''), "
      "auth_method::text, is_active, COALESCE(force_password_change, false) "
      "FROM users WHERE oidc_sub = $1",
      pqxx::params{sOidcSub});
  txn.commit();

  if (result.empty()) return std::nullopt;

  auto row = result[0];
  return UserRow{
      row[0].as<int64_t>(),
      row[1].as<std::string>(),
      row[2].as<std::string>(),
      row[3].as<std::string>(),
      row[4].as<std::string>(),
      row[5].as<bool>(),
      row[6].as<bool>(),
  };
}

std::optional<UserRow> UserRepository::findBySamlNameId(const std::string& sSamlNameId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT id, username, COALESCE(email, ''), COALESCE(password_hash, ''), "
      "auth_method::text, is_active, COALESCE(force_password_change, false) "
      "FROM users WHERE saml_name_id = $1",
      pqxx::params{sSamlNameId});
  txn.commit();

  if (result.empty()) return std::nullopt;

  auto row = result[0];
  return UserRow{
      row[0].as<int64_t>(),
      row[1].as<std::string>(),
      row[2].as<std::string>(),
      row[3].as<std::string>(),
      row[4].as<std::string>(),
      row[5].as<bool>(),
      row[6].as<bool>(),
  };
}

int64_t UserRepository::createFederated(const std::string& sUsername, const std::string& sEmail,
                                        const std::string& sAuthMethod,
                                        const std::string& sOidcSub,
                                        const std::string& sSamlNameId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "INSERT INTO users (username, email, auth_method, oidc_sub, saml_name_id) "
      "VALUES ($1, $2, $3::auth_method, NULLIF($4, ''), NULLIF($5, '')) RETURNING id",
      pqxx::params{sUsername, sEmail, sAuthMethod, sOidcSub, sSamlNameId});
  txn.commit();
  return result.one_row()[0].as<int64_t>();
}

void UserRepository::updateFederatedEmail(int64_t iUserId, const std::string& sEmail) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "UPDATE users SET email = $2, updated_at = NOW() WHERE id = $1",
      pqxx::params{iUserId, sEmail});
  txn.commit();

  if (result.affected_rows() == 0) {
    throw common::NotFoundError("USER_NOT_FOUND",
                                "User with id " + std::to_string(iUserId) + " not found");
  }
}

}  // namespace dns::dal
