#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace dns::dal {

class ConnectionPool;

/// Row type returned from variable queries.
struct VariableRow {
  int64_t iId = 0;
  std::string sName;
  std::string sValue;
  std::string sType;
  std::string sScope;
  std::optional<int64_t> oZoneId;
  std::chrono::system_clock::time_point tpCreatedAt;
  std::chrono::system_clock::time_point tpUpdatedAt;
};

/// Manages the variables table.
/// Class abbreviation: var
class VariableRepository {
 public:
  explicit VariableRepository(ConnectionPool& cpPool);
  ~VariableRepository();

  /// Create a variable. Returns the new ID.
  int64_t create(const std::string& sName, const std::string& sValue,
                 const std::string& sType, const std::string& sScope,
                 std::optional<int64_t> oZoneId);

  /// List all variables.
  std::vector<VariableRow> listAll();

  /// List variables by scope ('global' or 'zone').
  std::vector<VariableRow> listByScope(const std::string& sScope);

  /// List zone-scoped vars for a zone AND all global vars.
  std::vector<VariableRow> listByZoneId(int64_t iZoneId);

  /// Find a variable by ID. Returns nullopt if not found.
  std::optional<VariableRow> findById(int64_t iId);

  /// Update a variable's value only.
  void update(int64_t iId, const std::string& sValue);

  /// Delete a variable by ID. Throws NotFoundError if not found.
  void deleteById(int64_t iId);

 private:
  ConnectionPool& _cpPool;
};

}  // namespace dns::dal
