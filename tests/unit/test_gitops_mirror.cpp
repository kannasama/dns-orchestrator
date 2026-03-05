#include "gitops/GitOpsMirror.hpp"

#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

#include <nlohmann/json.hpp>
#include <pqxx/pqxx>

#include "common/Logger.hpp"
#include "core/VariableEngine.hpp"
#include "dal/ConnectionPool.hpp"
#include "dal/RecordRepository.hpp"
#include "dal/ViewRepository.hpp"
#include "dal/ZoneRepository.hpp"

namespace {
std::string getDbUrl() {
  const char* pUrl = std::getenv("DNS_DB_URL");
  return pUrl ? std::string(pUrl) : std::string{};
}
}  // namespace

class GitOpsMirrorSnapshotTest : public ::testing::Test {
 protected:
  void SetUp() override {
    _sDbUrl = getDbUrl();
    if (_sDbUrl.empty()) {
      GTEST_SKIP() << "DNS_DB_URL not set — skipping integration test";
    }
    dns::common::Logger::init("warn");
    _cpPool = std::make_unique<dns::dal::ConnectionPool>(_sDbUrl, 2);
    _vrRepo = std::make_unique<dns::dal::ViewRepository>(*_cpPool);
    _zrRepo = std::make_unique<dns::dal::ZoneRepository>(*_cpPool);
    _rrRepo = std::make_unique<dns::dal::RecordRepository>(*_cpPool);
    _veEngine = std::make_unique<dns::core::VariableEngine>();

    auto cg = _cpPool->checkout();
    pqxx::work txn(*cg);
    txn.exec("DELETE FROM records");
    txn.exec("DELETE FROM deployments");
    txn.exec("DELETE FROM variables");
    txn.exec("DELETE FROM zones");
    txn.exec("DELETE FROM view_providers");
    txn.exec("DELETE FROM views");
    txn.commit();

    _iViewId = _vrRepo->create("test-view", "Test view");
    _iZoneId = _zrRepo->create("example.com", _iViewId, std::nullopt);
    _rrRepo->create(_iZoneId, "www.example.com.", "A", 300, "1.2.3.4", 0);
    _rrRepo->create(_iZoneId, "mail.example.com.", "MX", 300, "mx.example.com.", 10);
  }

  std::string _sDbUrl;
  std::unique_ptr<dns::dal::ConnectionPool> _cpPool;
  std::unique_ptr<dns::dal::ViewRepository> _vrRepo;
  std::unique_ptr<dns::dal::ZoneRepository> _zrRepo;
  std::unique_ptr<dns::dal::RecordRepository> _rrRepo;
  std::unique_ptr<dns::core::VariableEngine> _veEngine;
  int64_t _iViewId = 0;
  int64_t _iZoneId = 0;
};

TEST_F(GitOpsMirrorSnapshotTest, BuildSnapshotJson) {
  dns::gitops::GitOpsMirror gm(*_zrRepo, *_vrRepo, *_rrRepo, *_veEngine);

  std::string sJson = gm.buildSnapshotJson(_iZoneId, "alice");
  auto j = nlohmann::json::parse(sJson);

  EXPECT_EQ(j["zone"], "example.com");
  EXPECT_EQ(j["view"], "test-view");
  EXPECT_EQ(j["generated_by"], "alice");
  ASSERT_TRUE(j.contains("records"));
  EXPECT_EQ(j["records"].size(), 2u);

  // Records should have expanded values (no {{var}} since templates are static)
  bool bFoundWww = false;
  for (const auto& rec : j["records"]) {
    if (rec["name"] == "www.example.com.") {
      EXPECT_EQ(rec["type"], "A");
      EXPECT_EQ(rec["value"], "1.2.3.4");
      EXPECT_EQ(rec["ttl"], 300);
      bFoundWww = true;
    }
  }
  EXPECT_TRUE(bFoundWww);
}
