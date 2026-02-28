#include "common/Config.hpp"

#include <gtest/gtest.h>

#include <cstdlib>
#include <fstream>
#include <string>

using namespace dns::common;

namespace {

/// RAII helper to set/unset env vars for tests.
class EnvGuard {
 public:
  explicit EnvGuard(const std::string& sName, const std::string& sValue)
      : _sName(sName) {
    setenv(_sName.c_str(), sValue.c_str(), 1);
  }
  ~EnvGuard() { unsetenv(_sName.c_str()); }
 private:
  std::string _sName;
};

void clearAllDnsEnv() {
  const char* vVars[] = {
      "DNS_DB_URL", "DNS_MASTER_KEY", "DNS_MASTER_KEY_FILE",
      "DNS_JWT_SECRET", "DNS_JWT_SECRET_FILE", "DNS_DB_POOL_SIZE",
      "DNS_JWT_ALGORITHM", "DNS_JWT_TTL_SECONDS", "DNS_HTTP_PORT",
      "DNS_HTTP_THREADS", "DNS_THREAD_POOL_SIZE", "DNS_LOG_LEVEL",
      "DNS_DEPLOYMENT_RETENTION_COUNT", "DNS_SESSION_ABSOLUTE_TTL_SECONDS",
      "DNS_SESSION_CLEANUP_INTERVAL_SECONDS", "DNS_AUDIT_STDOUT",
      "DNS_AUDIT_RETENTION_DAYS", "DNS_AUDIT_PURGE_INTERVAL_SECONDS",
      "DNS_AUDIT_DB_URL", "DNS_GIT_REMOTE_URL", "DNS_GIT_LOCAL_PATH",
      "DNS_GIT_SSH_KEY_PATH", "DNS_API_KEY_CLEANUP_GRACE_SECONDS",
      "DNS_API_KEY_CLEANUP_INTERVAL_SECONDS",
      nullptr};
  for (int i = 0; vVars[i] != nullptr; ++i) {
    unsetenv(vVars[i]);
  }
}

void setMinimumRequiredEnv() {
  setenv("DNS_DB_URL", "postgresql://test:test@localhost:5432/test_db", 1);
  setenv("DNS_MASTER_KEY",
         "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 1);
  setenv("DNS_JWT_SECRET", "test-jwt-secret-at-least-some-chars", 1);
}

}  // namespace

class ConfigTest : public ::testing::Test {
 protected:
  void SetUp() override { clearAllDnsEnv(); }
  void TearDown() override { clearAllDnsEnv(); }
};

TEST_F(ConfigTest, LoadWithAllRequiredVars) {
  setMinimumRequiredEnv();
  auto cfg = Config::load();
  EXPECT_EQ(cfg.sDbUrl, "postgresql://test:test@localhost:5432/test_db");
  EXPECT_EQ(cfg.sJwtAlgorithm, "HS256");
  EXPECT_EQ(cfg.iDbPoolSize, 10);
  EXPECT_EQ(cfg.iHttpPort, 8080);
}

TEST_F(ConfigTest, ThrowsOnMissingDbUrl) {
  setenv("DNS_MASTER_KEY",
         "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 1);
  setenv("DNS_JWT_SECRET", "secret", 1);

  EXPECT_THROW(Config::load(), std::runtime_error);
}

TEST_F(ConfigTest, ThrowsOnMissingMasterKey) {
  setenv("DNS_DB_URL", "postgresql://test:test@localhost:5432/test_db", 1);
  setenv("DNS_JWT_SECRET", "secret", 1);

  EXPECT_THROW(Config::load(), std::runtime_error);
}

TEST_F(ConfigTest, ThrowsOnMissingJwtSecret) {
  setenv("DNS_DB_URL", "postgresql://test:test@localhost:5432/test_db", 1);
  setenv("DNS_MASTER_KEY",
         "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 1);

  EXPECT_THROW(Config::load(), std::runtime_error);
}

TEST_F(ConfigTest, FallsBackToFileForMasterKey) {
  setenv("DNS_DB_URL", "postgresql://test:test@localhost:5432/test_db", 1);
  setenv("DNS_JWT_SECRET", "secret", 1);

  // Write a temp file
  const std::string sPath = "/tmp/dns_test_master_key";
  {
    std::ofstream ofs(sPath);
    ofs << "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n";
  }
  setenv("DNS_MASTER_KEY_FILE", sPath.c_str(), 1);

  auto cfg = Config::load();
  EXPECT_EQ(cfg.sMasterKey,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

  unsetenv("DNS_MASTER_KEY_FILE");
  std::remove(sPath.c_str());
}

TEST_F(ConfigTest, DeploymentRetentionCountMustBeAtLeastOne) {
  setMinimumRequiredEnv();
  setenv("DNS_DEPLOYMENT_RETENTION_COUNT", "0", 1);

  EXPECT_THROW(Config::load(), std::runtime_error);
}

TEST_F(ConfigTest, SessionAbsoluteTtlMustBeGreaterOrEqualJwtTtl) {
  setMinimumRequiredEnv();
  setenv("DNS_JWT_TTL_SECONDS", "3600", 1);
  setenv("DNS_SESSION_ABSOLUTE_TTL_SECONDS", "1800", 1);

  EXPECT_THROW(Config::load(), std::runtime_error);
}

TEST_F(ConfigTest, OverrideDefaults) {
  setMinimumRequiredEnv();
  setenv("DNS_DB_POOL_SIZE", "20", 1);
  setenv("DNS_HTTP_PORT", "9090", 1);
  setenv("DNS_LOG_LEVEL", "debug", 1);
  setenv("DNS_AUDIT_STDOUT", "true", 1);

  auto cfg = Config::load();
  EXPECT_EQ(cfg.iDbPoolSize, 20);
  EXPECT_EQ(cfg.iHttpPort, 9090);
  EXPECT_EQ(cfg.sLogLevel, "debug");
  EXPECT_TRUE(cfg.bAuditStdout);
}
