#pragma once

#include <chrono>
#include <cstdint>
#include <optional>

namespace dns::dal {

/// Result of a purge operation.
struct PurgeResult {
  int64_t iDeletedCount = 0;
  std::optional<std::chrono::system_clock::time_point> oOldestRemaining;
};

/// Manages the audit_log table; insert, bulk-insert, purgeOld.
class AuditRepository {
 public:
  AuditRepository();
  ~AuditRepository();

  PurgeResult purgeOld(int iRetentionDays);
};

}  // namespace dns::dal
