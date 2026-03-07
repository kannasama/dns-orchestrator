#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace dns::dal {

class ConnectionPool;

/// Row type returned from record queries.
struct RecordRow {
  int64_t iId = 0;
  int64_t iZoneId = 0;
  std::string sName;
  std::string sType;
  int iTtl = 300;
  std::string sValueTemplate;
  int iPriority = 0;
  std::optional<int64_t> oLastAuditId;
  std::chrono::system_clock::time_point tpCreatedAt;
  std::chrono::system_clock::time_point tpUpdatedAt;
};

/// Manages the records table (raw templates); upsert for rollback restore.
/// Class abbreviation: rr
class RecordRepository {
 public:
  explicit RecordRepository(ConnectionPool& cpPool);
  ~RecordRepository();

  /// Create a record. Returns the new ID.
  int64_t create(int64_t iZoneId, const std::string& sName, const std::string& sType,
                 int iTtl, const std::string& sValueTemplate, int iPriority);

  /// List records for a zone.
  std::vector<RecordRow> listByZoneId(int64_t iZoneId);

  /// Find a record by ID. Returns nullopt if not found.
  std::optional<RecordRow> findById(int64_t iId);

  /// Update a record.
  void update(int64_t iId, const std::string& sName, const std::string& sType,
              int iTtl, const std::string& sValueTemplate, int iPriority);

  /// Delete a record by ID. Throws NotFoundError if not found.
  void deleteById(int64_t iId);

  /// Delete all records for a zone. Returns deleted count.
  int deleteAllByZoneId(int64_t iZoneId);

  /// Create multiple records in a single transaction. Returns created IDs.
  /// Throws ValidationError with per-record details on failure.
  std::vector<int64_t> createBatch(int64_t iZoneId,
                                    const std::vector<std::tuple<std::string, std::string,
                                                                 int, std::string, int>>& vRecords);

  /// Upsert a record by ID. If the ID exists, update it. Otherwise, create a new record.
  /// Returns the record ID (existing or newly created).
  int64_t upsertById(int64_t iId, int64_t iZoneId, const std::string& sName,
                     const std::string& sType, int iTtl,
                     const std::string& sValueTemplate, int iPriority);

 private:
  ConnectionPool& _cpPool;
};

}  // namespace dns::dal
