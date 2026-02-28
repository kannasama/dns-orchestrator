#include "common/Config.hpp"

#include "common/Errors.hpp"
#include "common/Logger.hpp"

#include <openssl/crypto.h>

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>

namespace dns::common {

std::string Config::getEnv(const char* pVarName) {
  const char* pValue = std::getenv(pVarName);
  return pValue ? std::string(pValue) : std::string{};
}

int Config::getEnvInt(const char* pVarName, int iDefault) {
  const std::string sValue = getEnv(pVarName);
  if (sValue.empty()) {
    return iDefault;
  }
  try {
    return std::stoi(sValue);
  } catch (...) {
    throw std::runtime_error(
        std::string("Invalid integer value for ") + pVarName + ": " + sValue);
  }
}

bool Config::getEnvBool(const char* pVarName, bool bDefault) {
  const std::string sValue = getEnv(pVarName);
  if (sValue.empty()) {
    return bDefault;
  }
  return sValue == "true" || sValue == "1" || sValue == "yes";
}

std::string Config::loadSecret(const char* pVarName) {
  // Try the direct env var first
  std::string sValue = getEnv(pVarName);
  if (!sValue.empty()) {
    return sValue;
  }

  // Try _FILE fallback
  const std::string sFileVar = std::string(pVarName) + "_FILE";
  const std::string sFilePath = getEnv(sFileVar.c_str());
  if (sFilePath.empty()) {
    throw std::runtime_error(
        std::string("Required secret not set: neither ") + pVarName + " nor " + sFileVar +
        " is defined");
  }

  // Read file contents
  std::ifstream ifs(sFilePath);
  if (!ifs.is_open()) {
    throw std::runtime_error(
        std::string("Cannot open secret file specified by ") + sFileVar + ": " + sFilePath);
  }

  std::ostringstream oss;
  oss << ifs.rdbuf();
  sValue = oss.str();

  // Trim trailing whitespace/newlines
  while (!sValue.empty() &&
         (sValue.back() == '\n' || sValue.back() == '\r' || sValue.back() == ' ')) {
    sValue.pop_back();
  }

  if (sValue.empty()) {
    throw std::runtime_error(
        std::string("Secret file is empty: ") + sFilePath + " (from " + sFileVar + ")");
  }

  return sValue;
}

Config Config::load() {
  Config cfg;

  // ── Required vars ──────────────────────────────────────────────────────
  cfg.sDbUrl = getEnv("DNS_DB_URL");
  if (cfg.sDbUrl.empty()) {
    throw std::runtime_error("Required environment variable DNS_DB_URL is not set");
  }

  // Secrets with _FILE fallback (SEC-02)
  cfg.sMasterKey = loadSecret("DNS_MASTER_KEY");
  cfg.sJwtSecret = loadSecret("DNS_JWT_SECRET");

  // ── Optional vars with defaults ────────────────────────────────────────
  cfg.iDbPoolSize = getEnvInt("DNS_DB_POOL_SIZE", 10);
  cfg.sJwtAlgorithm = getEnv("DNS_JWT_ALGORITHM");
  if (cfg.sJwtAlgorithm.empty()) {
    cfg.sJwtAlgorithm = "HS256";
  }
  cfg.iJwtTtlSeconds = getEnvInt("DNS_JWT_TTL_SECONDS", 28800);
  cfg.iHttpPort = getEnvInt("DNS_HTTP_PORT", 8080);
  cfg.iHttpThreads = getEnvInt("DNS_HTTP_THREADS", 4);
  cfg.iThreadPoolSize = getEnvInt("DNS_THREAD_POOL_SIZE", 0);

  // GitOps
  const std::string sGitUrl = getEnv("DNS_GIT_REMOTE_URL");
  if (!sGitUrl.empty()) {
    cfg.oGitRemoteUrl = sGitUrl;
  }
  const std::string sGitPath = getEnv("DNS_GIT_LOCAL_PATH");
  if (!sGitPath.empty()) {
    cfg.sGitLocalPath = sGitPath;
  }
  const std::string sGitKey = getEnv("DNS_GIT_SSH_KEY_PATH");
  if (!sGitKey.empty()) {
    cfg.oGitSshKeyPath = sGitKey;
  }

  // Logging
  const std::string sLogLevel = getEnv("DNS_LOG_LEVEL");
  if (!sLogLevel.empty()) {
    cfg.sLogLevel = sLogLevel;
  }

  // Session
  cfg.iSessionAbsoluteTtlSeconds = getEnvInt("DNS_SESSION_ABSOLUTE_TTL_SECONDS", 86400);
  cfg.iSessionCleanupIntervalSeconds = getEnvInt("DNS_SESSION_CLEANUP_INTERVAL_SECONDS", 3600);

  // API key
  cfg.iApiKeyCleanupGraceSeconds = getEnvInt("DNS_API_KEY_CLEANUP_GRACE_SECONDS", 300);
  cfg.iApiKeyCleanupIntervalSeconds = getEnvInt("DNS_API_KEY_CLEANUP_INTERVAL_SECONDS", 3600);

  // Deployment
  cfg.iDeploymentRetentionCount = getEnvInt("DNS_DEPLOYMENT_RETENTION_COUNT", 10);

  // Audit
  const std::string sAuditDbUrl = getEnv("DNS_AUDIT_DB_URL");
  if (!sAuditDbUrl.empty()) {
    cfg.oAuditDbUrl = sAuditDbUrl;
  }
  cfg.bAuditStdout = getEnvBool("DNS_AUDIT_STDOUT", false);
  cfg.iAuditRetentionDays = getEnvInt("DNS_AUDIT_RETENTION_DAYS", 365);
  cfg.iAuditPurgeIntervalSeconds = getEnvInt("DNS_AUDIT_PURGE_INTERVAL_SECONDS", 86400);

  // ── Validation ─────────────────────────────────────────────────────────

  // DNS_DEPLOYMENT_RETENTION_COUNT >= 1
  if (cfg.iDeploymentRetentionCount < 1) {
    throw std::runtime_error(
        "DNS_DEPLOYMENT_RETENTION_COUNT must be >= 1 (got " +
        std::to_string(cfg.iDeploymentRetentionCount) + ")");
  }

  // DNS_SESSION_ABSOLUTE_TTL_SECONDS >= DNS_JWT_TTL_SECONDS
  if (cfg.iSessionAbsoluteTtlSeconds < cfg.iJwtTtlSeconds) {
    throw std::runtime_error(
        "DNS_SESSION_ABSOLUTE_TTL_SECONDS (" + std::to_string(cfg.iSessionAbsoluteTtlSeconds) +
        ") must be >= DNS_JWT_TTL_SECONDS (" + std::to_string(cfg.iJwtTtlSeconds) + ")");
  }

  return cfg;
}

}  // namespace dns::common
