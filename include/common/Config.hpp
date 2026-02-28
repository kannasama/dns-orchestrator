#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>

namespace dns::common {

/// Environment variable loader implementing ARCHITECTURE.md §8.
/// Class abbreviation: cfg
struct Config {
  // Required
  std::string sDbUrl;
  std::string sMasterKey;
  std::string sJwtSecret;

  // Database
  int iDbPoolSize = 10;

  // JWT
  std::string sJwtAlgorithm = "HS256";
  int iJwtTtlSeconds = 28800;

  // HTTP
  int iHttpPort = 8080;
  int iHttpThreads = 4;

  // Thread pool
  int iThreadPoolSize = 0;  // 0 = hardware_concurrency

  // GitOps
  std::optional<std::string> oGitRemoteUrl;
  std::string sGitLocalPath = "/var/dns-orchestrator/repo";
  std::optional<std::string> oGitSshKeyPath;

  // Logging
  std::string sLogLevel = "info";

  // Session
  int iSessionAbsoluteTtlSeconds = 86400;
  int iSessionCleanupIntervalSeconds = 3600;

  // API key
  int iApiKeyCleanupGraceSeconds = 300;
  int iApiKeyCleanupIntervalSeconds = 3600;

  // Deployment
  int iDeploymentRetentionCount = 10;

  // Audit
  std::optional<std::string> oAuditDbUrl;
  bool bAuditStdout = false;
  int iAuditRetentionDays = 365;
  int iAuditPurgeIntervalSeconds = 86400;

  /// Load and validate all config from environment variables.
  /// Throws on missing required vars or invalid constraints.
  static Config load();
};

}  // namespace dns::common
