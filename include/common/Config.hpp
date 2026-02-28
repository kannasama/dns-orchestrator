#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>

namespace dns::common {

/// Environment variable loader implementing ARCHITECTURE.md §8.
/// Loads all env vars into a typed struct with validation.
/// Class abbreviation: cfg
struct Config {
  // ── Required ──────────────────────────────────────────────────────────
  std::string sDbUrl;
  std::string sMasterKey;   // raw hex string (zeroed after handoff to CryptoService)
  std::string sJwtSecret;   // raw secret (zeroed after handoff to IJwtSigner)

  // ── Database ──────────────────────────────────────────────────────────
  int iDbPoolSize = 10;

  // ── JWT ────────────────────────────────────────────────────────────────
  std::string sJwtAlgorithm = "HS256";
  int iJwtTtlSeconds = 28800;

  // ── HTTP ──────────────────────────────────────────────────────────────
  int iHttpPort = 8080;
  int iHttpThreads = 4;

  // ── Thread pool ───────────────────────────────────────────────────────
  int iThreadPoolSize = 0;  // 0 = std::thread::hardware_concurrency()

  // ── GitOps ────────────────────────────────────────────────────────────
  std::optional<std::string> oGitRemoteUrl;
  std::string sGitLocalPath = "/var/dns-orchestrator/repo";
  std::optional<std::string> oGitSshKeyPath;

  // ── Logging ───────────────────────────────────────────────────────────
  std::string sLogLevel = "info";

  // ── Session ───────────────────────────────────────────────────────────
  int iSessionAbsoluteTtlSeconds = 86400;
  int iSessionCleanupIntervalSeconds = 3600;

  // ── API key ───────────────────────────────────────────────────────────
  int iApiKeyCleanupGraceSeconds = 300;
  int iApiKeyCleanupIntervalSeconds = 3600;

  // ── Deployment ────────────────────────────────────────────────────────
  int iDeploymentRetentionCount = 10;

  // ── Audit ─────────────────────────────────────────────────────────────
  std::optional<std::string> oAuditDbUrl;
  bool bAuditStdout = false;
  int iAuditRetentionDays = 365;
  int iAuditPurgeIntervalSeconds = 86400;

  /// Load and validate all config from environment variables.
  /// Implements _FILE fallback for DNS_MASTER_KEY and DNS_JWT_SECRET.
  /// Calls OPENSSL_cleanse() on raw secret strings after loading.
  /// Throws on missing required vars or invalid constraints.
  static Config load();

 private:
  /// Read an env var with optional _FILE fallback for secrets.
  /// If varName is unset, tries varName + "_FILE" and reads file contents.
  /// Trims trailing whitespace/newlines from file contents.
  static std::string loadSecret(const char* pVarName);

  /// Read an env var, return empty string if unset.
  static std::string getEnv(const char* pVarName);

  /// Read an env var as int with a default value.
  static int getEnvInt(const char* pVarName, int iDefault);

  /// Read an env var as bool (true/false/1/0), default false.
  static bool getEnvBool(const char* pVarName, bool bDefault);
};

}  // namespace dns::common
