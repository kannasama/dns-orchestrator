#include "core/RollbackEngine.hpp"

#include <gtest/gtest.h>

#include <cstdlib>
#include <string>

#include <nlohmann/json.hpp>
#include <pqxx/pqxx>

#include "common/Errors.hpp"
#include "common/Logger.hpp"
#include "dal/AuditRepository.hpp"
#include "dal/ConnectionPool.hpp"
#include "dal/DeploymentRepository.hpp"
#include "dal/RecordRepository.hpp"
#include "dal/ViewRepository.hpp"
#include "dal/ZoneRepository.hpp"

namespace {
std::string getDbUrl() {
  const char* pUrl = std::getenv("DNS_DB_URL");
  return pUrl ? std::string(pUrl) : std::string{};
}
}  // namespace

class RollbackEngineTest : public ::testing::Test {
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
    _drRepo = std::make_unique<dns::dal::DeploymentRepository>(*_cpPool);
    _arRepo = std::make_unique<dns::dal::AuditRepository>(*_cpPool);

    auto cg = _cpPool->checkout();
    pqxx::work txn(*cg);
    txn.exec("DELETE FROM audit_log");
    txn.exec("DELETE FROM records");
    txn.exec("DELETE FROM deployments");
    txn.exec("DELETE FROM variables");
    txn.exec("DELETE FROM zones");
    txn.exec("DELETE FROM view_providers");
    txn.exec("DELETE FROM views");
    txn.commit();

    _iViewId = _vrRepo->create("ext", "External");
    _iZoneId = _zrRepo->create("example.com", _iViewId, std::nullopt);

    // Create a user for deployed_by
    {
      auto cg2 = _cpPool->checkout();
      pqxx::work txn2(*cg2);
      txn2.exec("DELETE FROM sessions");
      txn2.exec("DELETE FROM api_keys");
      txn2.exec("DELETE FROM group_members");
      txn2.exec("DELETE FROM users");
      auto r = txn2.exec(
          "INSERT INTO users (username, auth_method) VALUES ('alice', 'local') RETURNING id");
      _iUserId = r[0][0].as<int64_t>();
      txn2.commit();
    }
  }

  std::string _sDbUrl;
  std::unique_ptr<dns::dal::ConnectionPool> _cpPool;
  std::unique_ptr<dns::dal::ViewRepository> _vrRepo;
  std::unique_ptr<dns::dal::ZoneRepository> _zrRepo;
  std::unique_ptr<dns::dal::RecordRepository> _rrRepo;
  std::unique_ptr<dns::dal::DeploymentRepository> _drRepo;
  std::unique_ptr<dns::dal::AuditRepository> _arRepo;
  int64_t _iViewId = 0;
  int64_t _iZoneId = 0;
  int64_t _iUserId = 0;
};

TEST_F(RollbackEngineTest, FullRestore) {
  // Create original records
  int64_t iRec1 = _rrRepo->create(_iZoneId, "www", "A", 300, "1.2.3.4", 0);
  int64_t iRec2 = _rrRepo->create(_iZoneId, "mail", "MX", 300, "mx.example.com.", 10);

  // Save a deployment snapshot
  nlohmann::json jSnapshot = {
      {"zone", "example.com"},
      {"view", "ext"},
      {"deployed_by", "alice"},
      {"records", {{{"record_id", iRec1}, {"name", "www"}, {"type", "A"}, {"ttl", 300},
                    {"value_template", "1.2.3.4"}, {"value", "1.2.3.4"}, {"priority", 0}},
                   {{"record_id", iRec2}, {"name", "mail"}, {"type", "MX"}, {"ttl", 300},
                    {"value_template", "mx.example.com."}, {"value", "mx.example.com."},
                    {"priority", 10}}}},
  };
  int64_t iDeployId = _drRepo->create(_iZoneId, _iUserId, jSnapshot);

  // Now modify records (simulate changes after deployment)
  _rrRepo->update(iRec1, "www", "A", 600, "9.9.9.9", 0);
  _rrRepo->deleteById(iRec2);
  _rrRepo->create(_iZoneId, "new", "CNAME", 300, "other.com.", 0);

  // Rollback to the snapshot (full restore)
  dns::core::RollbackEngine reEngine(*_drRepo, *_rrRepo, *_arRepo);
  reEngine.apply(_iZoneId, iDeployId, {}, _iUserId, "alice");

  // Verify records match snapshot
  auto vRecords = _rrRepo->listByZoneId(_iZoneId);
  EXPECT_EQ(vRecords.size(), 2u);

  bool bFoundWww = false, bFoundMail = false;
  for (const auto& rec : vRecords) {
    if (rec.sName == "www") {
      EXPECT_EQ(rec.sValueTemplate, "1.2.3.4");
      EXPECT_EQ(rec.iTtl, 300);
      bFoundWww = true;
    }
    if (rec.sName == "mail") {
      EXPECT_EQ(rec.sValueTemplate, "mx.example.com.");
      bFoundMail = true;
    }
  }
  EXPECT_TRUE(bFoundWww);
  EXPECT_TRUE(bFoundMail);
}

TEST_F(RollbackEngineTest, CherryPickRestore) {
  int64_t iRec1 = _rrRepo->create(_iZoneId, "www", "A", 300, "1.2.3.4", 0);
  int64_t iRec2 = _rrRepo->create(_iZoneId, "mail", "MX", 300, "mx.example.com.", 10);

  nlohmann::json jSnapshot = {
      {"zone", "example.com"},
      {"records", {{{"record_id", iRec1}, {"name", "www"}, {"type", "A"}, {"ttl", 300},
                    {"value_template", "1.2.3.4"}, {"value", "1.2.3.4"}, {"priority", 0}},
                   {{"record_id", iRec2}, {"name", "mail"}, {"type", "MX"}, {"ttl", 300},
                    {"value_template", "mx.example.com."}, {"value", "mx.example.com."},
                    {"priority", 10}}}},
  };
  int64_t iDeployId = _drRepo->create(_iZoneId, _iUserId, jSnapshot);

  // Modify both records
  _rrRepo->update(iRec1, "www", "A", 600, "9.9.9.9", 0);
  _rrRepo->update(iRec2, "mail", "MX", 600, "mx2.example.com.", 10);

  // Cherry-pick restore only iRec1
  dns::core::RollbackEngine reEngine(*_drRepo, *_rrRepo, *_arRepo);
  reEngine.apply(_iZoneId, iDeployId, {iRec1}, _iUserId, "alice");

  // www should be restored, mail should keep its modified value
  auto oRec1 = _rrRepo->findById(iRec1);
  ASSERT_TRUE(oRec1.has_value());
  EXPECT_EQ(oRec1->sValueTemplate, "1.2.3.4");
  EXPECT_EQ(oRec1->iTtl, 300);

  auto oRec2 = _rrRepo->findById(iRec2);
  ASSERT_TRUE(oRec2.has_value());
  EXPECT_EQ(oRec2->sValueTemplate, "mx2.example.com.");
  EXPECT_EQ(oRec2->iTtl, 600);
}

TEST_F(RollbackEngineTest, RollbackNonexistentDeploymentThrows) {
  dns::core::RollbackEngine reEngine(*_drRepo, *_rrRepo, *_arRepo);
  EXPECT_THROW(reEngine.apply(_iZoneId, 99999, {}, _iUserId, "alice"),
               dns::common::NotFoundError);
}

TEST_F(RollbackEngineTest, RollbackCreatesAuditEntry) {
  int64_t iRec1 = _rrRepo->create(_iZoneId, "www", "A", 300, "1.2.3.4", 0);
  nlohmann::json jSnapshot = {
      {"zone", "example.com"},
      {"records", {{{"record_id", iRec1}, {"name", "www"}, {"type", "A"}, {"ttl", 300},
                    {"value_template", "1.2.3.4"}, {"value", "1.2.3.4"}, {"priority", 0}}}},
  };
  int64_t iDeployId = _drRepo->create(_iZoneId, _iUserId, jSnapshot);

  dns::core::RollbackEngine reEngine(*_drRepo, *_rrRepo, *_arRepo);
  reEngine.apply(_iZoneId, iDeployId, {}, _iUserId, "alice");

  auto vAudit = _arRepo->query(std::string("zone"), std::nullopt, std::string("alice"),
                               std::nullopt, std::nullopt, 10);
  ASSERT_FALSE(vAudit.empty());
  EXPECT_EQ(vAudit[0].sOperation, "rollback");
}
