#include "dal/GroupRepository.hpp"

#include "common/Errors.hpp"
#include "dal/ConnectionPool.hpp"

#include <pqxx/pqxx>

namespace dns::dal {

GroupRepository::GroupRepository(ConnectionPool& cpPool) : _cpPool(cpPool) {}

std::vector<GroupRow> GroupRepository::listAll() {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT g.id, g.name, COALESCE(g.description, ''), "
      "EXTRACT(EPOCH FROM g.created_at)::bigint, "
      "COUNT(gm.user_id)::int "
      "FROM groups g "
      "LEFT JOIN group_members gm ON gm.group_id = g.id "
      "GROUP BY g.id ORDER BY g.name");
  txn.commit();

  std::vector<GroupRow> vGroups;
  vGroups.reserve(result.size());
  for (const auto& row : result) {
    vGroups.push_back({
        row[0].as<int64_t>(),
        row[1].as<std::string>(),
        row[2].as<std::string>(),
        row[4].as<int>(),
        std::chrono::system_clock::time_point(std::chrono::seconds(row[3].as<int64_t>())),
    });
  }
  return vGroups;
}

std::optional<GroupRow> GroupRepository::findById(int64_t iGroupId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT g.id, g.name, COALESCE(g.description, ''), "
      "EXTRACT(EPOCH FROM g.created_at)::bigint, "
      "COUNT(gm.user_id)::int "
      "FROM groups g "
      "LEFT JOIN group_members gm ON gm.group_id = g.id "
      "WHERE g.id = $1 GROUP BY g.id",
      pqxx::params{iGroupId});
  txn.commit();

  if (result.empty()) return std::nullopt;
  const auto& row = result[0];
  return GroupRow{
      row[0].as<int64_t>(),
      row[1].as<std::string>(),
      row[2].as<std::string>(),
      row[4].as<int>(),
      std::chrono::system_clock::time_point(std::chrono::seconds(row[3].as<int64_t>())),
  };
}

int64_t GroupRepository::create(const std::string& sName, const std::string& sDescription) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  try {
    auto result = txn.exec(
        "INSERT INTO groups (name, description) VALUES ($1, $2) RETURNING id",
        pqxx::params{sName, sDescription});
    txn.commit();
    return result[0][0].as<int64_t>();
  } catch (const pqxx::unique_violation&) {
    throw common::ConflictError("GROUP_EXISTS", "Group name already exists");
  }
}

void GroupRepository::update(int64_t iGroupId, const std::string& sName,
                             const std::string& sDescription) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "UPDATE groups SET name = $1, description = $2 WHERE id = $3",
      pqxx::params{sName, sDescription, iGroupId});
  txn.commit();
  if (result.affected_rows() == 0)
    throw common::NotFoundError("GROUP_NOT_FOUND", "Group not found");
}

void GroupRepository::deleteGroup(int64_t iGroupId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);

  auto check = txn.exec(
      "SELECT gm.user_id FROM group_members gm "
      "WHERE gm.group_id = $1 "
      "AND NOT EXISTS ("
      "  SELECT 1 FROM group_members gm2 "
      "  WHERE gm2.user_id = gm.user_id AND gm2.group_id != $1"
      ")",
      pqxx::params{iGroupId});

  if (!check.empty())
    throw common::ConflictError("GROUP_SOLE_MEMBERSHIP",
        "Cannot delete: group is the only group for one or more users");

  auto result = txn.exec("DELETE FROM groups WHERE id = $1", pqxx::params{iGroupId});
  txn.commit();

  if (result.affected_rows() == 0)
    throw common::NotFoundError("GROUP_NOT_FOUND", "Group not found");
}

std::vector<GroupMemberRow> GroupRepository::listMembers(int64_t iGroupId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT u.id, u.username, gm.role_id, r.name, "
      "COALESCE(gm.scope_type, ''), COALESCE(gm.scope_id, 0) "
      "FROM users u "
      "JOIN group_members gm ON gm.user_id = u.id "
      "JOIN roles r ON r.id = gm.role_id "
      "WHERE gm.group_id = $1 ORDER BY u.username",
      pqxx::params{iGroupId});
  txn.commit();

  std::vector<GroupMemberRow> vMembers;
  vMembers.reserve(result.size());
  for (const auto& row : result) {
    vMembers.push_back({
        row[0].as<int64_t>(),
        row[1].as<std::string>(),
        row[2].as<int64_t>(),
        row[3].as<std::string>(),
        row[4].as<std::string>(),
        row[5].as<int64_t>(),
    });
  }
  return vMembers;
}

void GroupRepository::addMember(int64_t iGroupId, int64_t iUserId, int64_t iRoleId,
                                 const std::string& sScopeType, int64_t iScopeId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  try {
    if (sScopeType.empty()) {
      txn.exec(
          "INSERT INTO group_members (user_id, group_id, role_id) VALUES ($1, $2, $3)",
          pqxx::params{iUserId, iGroupId, iRoleId});
    } else {
      txn.exec(
          "INSERT INTO group_members (user_id, group_id, role_id, scope_type, scope_id) "
          "VALUES ($1, $2, $3, $4, $5)",
          pqxx::params{iUserId, iGroupId, iRoleId, sScopeType, iScopeId});
    }
    txn.commit();
  } catch (const pqxx::unique_violation&) {
    throw common::ConflictError("MEMBER_EXISTS",
                                 "Member already exists with this role and scope");
  }
}

void GroupRepository::removeMember(int64_t iGroupId, int64_t iUserId, int64_t iRoleId,
                                    const std::string& sScopeType, int64_t iScopeId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  pqxx::result result;
  if (sScopeType.empty()) {
    result = txn.exec(
        "DELETE FROM group_members "
        "WHERE user_id = $1 AND group_id = $2 AND role_id = $3 AND scope_type IS NULL",
        pqxx::params{iUserId, iGroupId, iRoleId});
  } else {
    result = txn.exec(
        "DELETE FROM group_members "
        "WHERE user_id = $1 AND group_id = $2 AND role_id = $3 "
        "AND scope_type = $4 AND scope_id = $5",
        pqxx::params{iUserId, iGroupId, iRoleId, sScopeType, iScopeId});
  }
  txn.commit();
  if (result.affected_rows() == 0)
    throw common::NotFoundError("MEMBER_NOT_FOUND", "Member assignment not found");
}

}  // namespace dns::dal
