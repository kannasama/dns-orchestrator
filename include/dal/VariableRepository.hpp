#pragma once

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
  std::string sCreatedAt;
  std::string sUpdatedAt;
};

/// Manages the variables table.
/// Class abbreviation: var
class VariableRepository {
 public:
  explicit VariableRepository(ConnectionPool& cpPool);
  ~VariableRepository();

  /// Create a variable. Returns the new variable ID.
  /// Throws ConflictError if (name, zone_id) already exists.
  int64_t create(const std::string& sName, const std::string& sValue,
                 const std::string& sType, const std::string& sScope,
                 std::optional<int64_t> oZoneId);

  /// Find a variable by ID. Returns nullopt if not found.
  std::optional<VariableRow> findById(int64_t iVariableId);

  /// Find a variable by name and zone_id.
  /// For global lookup, pass oZoneId = std::nullopt.
  /// Returns nullopt if not found.
  std::optional<VariableRow> findByName(const std::string& sName,
                                        std::optional<int64_t> oZoneId);

  /// List variables, optionally filtered by scope and/or zone_id.
  std::vector<VariableRow> list(std::optional<std::string> oScope,
                                std::optional<int64_t> oZoneId);

  /// Update a variable's name, value, and type.
  /// Throws NotFoundError if variable doesn't exist.
  void update(int64_t iVariableId, const std::string& sName,
              const std::string& sValue, const std::string& sType);

  /// Delete a variable by ID.
  /// Throws NotFoundError if variable doesn't exist.
  void deleteById(int64_t iVariableId);

 private:
  ConnectionPool& _cpPool;
};

}  // namespace dns::dal
