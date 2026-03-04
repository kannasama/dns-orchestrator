#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace dns::dal {

class ConnectionPool;

/// Row type returned from audit log queries.
struct AuditLogRow {
  int64_t iId = 0;
  std::string sEntityType;
  std::optional<int64_t> oEntityId;
  std::string sOperation;
  std::optional<nlohmann::json> ojOldValue;
  std::optional<nlohmann::json> ojNewValue;
  std::optional<std::string> osVariableUsed;
  std::string sIdentity;
  std::optional<std::string> osAuthMethod;
  std::optional<std::string> osIpAddress;
  std::chrono::system_clock::time_point tpTimestamp;
};

/// Result of a purge operation.
struct PurgeResult {
  int64_t iDeletedCount = 0;
  std::optional<std::chrono::system_clock::time_point> oOldestRemaining;
};

/// Manages the audit_log table; insert, query, purgeOld.
/// Class abbreviation: ar
class AuditRepository {
 public:
  explicit AuditRepository(ConnectionPool& cpPool);
  ~AuditRepository();

  /// Insert an audit log entry. Returns the new ID.
  int64_t insert(const std::string& sEntityType, std::optional<int64_t> oEntityId,
                 const std::string& sOperation,
                 const std::optional<nlohmann::json>& ojOldValue,
                 const std::optional<nlohmann::json>& ojNewValue,
                 const std::string& sIdentity,
                 const std::optional<std::string>& osAuthMethod,
                 const std::optional<std::string>& osIpAddress);

  /// Query audit log with optional filters. Orders by timestamp DESC.
  std::vector<AuditLogRow> query(
      const std::optional<std::string>& osEntityType,
      const std::optional<int64_t>& oEntityId,
      const std::optional<std::string>& osIdentity,
      const std::optional<std::chrono::system_clock::time_point>& otpFrom,
      const std::optional<std::chrono::system_clock::time_point>& otpTo,
      int iLimit = 100);

  /// Delete audit entries older than iRetentionDays. Returns count + oldest remaining.
  PurgeResult purgeOld(int iRetentionDays);

 private:
  ConnectionPool& _cpPool;
};

}  // namespace dns::dal
