#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace dns::common {

/// DNS record as seen by providers.
/// Class abbreviation: dr
struct DnsRecord {
  std::string sProviderRecordId;
  std::string sName;
  std::string sType;
  uint32_t uTtl = 300;
  std::string sValue;
  int iPriority = 0;
};

/// Provider health status.
enum class HealthStatus { Ok, Degraded, Unreachable };

/// Result of a provider push operation.
/// Class abbreviation: prs
struct PushResult {
  bool bSuccess = false;
  std::string sProviderRecordId;
  std::string sErrorMessage;
};

/// Diff action type.
enum class DiffAction { Add, Update, Delete, Drift };

/// A single record diff entry.
/// Class abbreviation: rd
struct RecordDiff {
  DiffAction action;
  std::string sName;
  std::string sType;
  std::string sProviderValue;
  std::string sSourceValue;
};

/// Result of a preview/diff operation.
/// Class abbreviation: pr
struct PreviewResult {
  int64_t iZoneId = 0;
  std::string sZoneName;
  std::vector<RecordDiff> vDiffs;
  bool bHasDrift = false;
  std::chrono::system_clock::time_point tpGeneratedAt;
};

/// Identity context injected by AuthMiddleware.
/// Class abbreviation: rc
struct RequestContext {
  int64_t iUserId = 0;
  std::string sUsername;
  std::string sRole;
  std::string sAuthMethod;
};

}  // namespace dns::common
