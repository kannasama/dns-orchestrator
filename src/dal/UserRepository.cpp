#include "dal/UserRepository.hpp"

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
      "auth_method::text, is_active "
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
  };
}

std::optional<UserRow> UserRepository::findById(int64_t iUserId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT id, username, COALESCE(email, ''), COALESCE(password_hash, ''), "
      "auth_method::text, is_active "
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

std::string UserRepository::getHighestRole(int64_t iUserId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);

  // Role priority: admin > operator > viewer
  // Use CASE to assign numeric priority, take the max
  auto result = txn.exec(
      "SELECT g.role::text FROM groups g "
      "JOIN group_members gm ON gm.group_id = g.id "
      "WHERE gm.user_id = $1 "
      "ORDER BY CASE g.role::text "
      "  WHEN 'admin' THEN 3 "
      "  WHEN 'operator' THEN 2 "
      "  WHEN 'viewer' THEN 1 "
      "END DESC "
      "LIMIT 1",
      pqxx::params{iUserId});
  txn.commit();

  if (result.empty()) return "";
  return result[0][0].as<std::string>();
}

}  // namespace dns::dal
