#include "api/ApiServer.hpp"
#include "api/AuthMiddleware.hpp"
#include "api/routes/AuditRoutes.hpp"
#include "api/routes/AuthRoutes.hpp"
#include "api/routes/DeploymentRoutes.hpp"
#include "api/routes/HealthRoutes.hpp"
#include "api/routes/ProviderRoutes.hpp"
#include "api/routes/RecordRoutes.hpp"
#include "api/routes/SetupRoutes.hpp"
#include "api/routes/VariableRoutes.hpp"
#include "api/routes/ViewRoutes.hpp"
#include "api/routes/ZoneRoutes.hpp"
#include "common/Logger.hpp"
#include "core/DeploymentEngine.hpp"
#include "core/DiffEngine.hpp"
#include "core/RollbackEngine.hpp"
#include "core/VariableEngine.hpp"
#include "dal/ApiKeyRepository.hpp"
#include "dal/AuditRepository.hpp"
#include "dal/ConnectionPool.hpp"
#include "dal/DeploymentRepository.hpp"
#include "dal/ProviderRepository.hpp"
#include "dal/RecordRepository.hpp"
#include "dal/RoleRepository.hpp"
#include "dal/SessionRepository.hpp"
#include "dal/UserRepository.hpp"
#include "dal/VariableRepository.hpp"
#include "dal/ViewRepository.hpp"
#include "dal/ZoneRepository.hpp"
#include "security/AuthService.hpp"
#include "security/CryptoService.hpp"
#include "security/HmacJwtSigner.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <cstdlib>
#include <string>

using dns::dal::ConnectionPool;

namespace {

std::string getDbUrl() {
  const char* pUrl = std::getenv("DNS_DB_URL");
  return pUrl ? std::string(pUrl) : std::string{};
}

const std::string kTestMasterKey =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const std::string kTestJwtSecret =
    "test-jwt-secret-that-is-at-least-32-bytes-long!!";

}  // namespace

class CrudRoutesTest : public ::testing::Test {
 protected:
  void SetUp() override {
    _sDbUrl = getDbUrl();
    if (_sDbUrl.empty()) {
      GTEST_SKIP() << "DNS_DB_URL not set — skipping integration test";
    }
    dns::common::Logger::init("warn");
    _cpPool = std::make_unique<ConnectionPool>(_sDbUrl, 2);
    _csService = std::make_unique<dns::security::CryptoService>(kTestMasterKey);
    _jsSigner = std::make_unique<dns::security::HmacJwtSigner>(kTestJwtSecret);

    // Repos
    _urRepo = std::make_unique<dns::dal::UserRepository>(*_cpPool);
    _srRepo = std::make_unique<dns::dal::SessionRepository>(*_cpPool);
    _akrRepo = std::make_unique<dns::dal::ApiKeyRepository>(*_cpPool);
    _prRepo = std::make_unique<dns::dal::ProviderRepository>(*_cpPool, *_csService);
    _vrRepo = std::make_unique<dns::dal::ViewRepository>(*_cpPool);
    _zrRepo = std::make_unique<dns::dal::ZoneRepository>(*_cpPool);
    _rrRepo = std::make_unique<dns::dal::RecordRepository>(*_cpPool);
    _varRepo = std::make_unique<dns::dal::VariableRepository>(*_cpPool);
    _drRepo = std::make_unique<dns::dal::DeploymentRepository>(*_cpPool);
    _arRepo = std::make_unique<dns::dal::AuditRepository>(*_cpPool);
    _roleRepo = std::make_unique<dns::dal::RoleRepository>(*_cpPool);

    // Engines
    _veEngine = std::make_unique<dns::core::VariableEngine>(*_varRepo);
    _deEngine = std::make_unique<dns::core::DiffEngine>(
        *_zrRepo, *_vrRepo, *_rrRepo, *_prRepo, *_veEngine);
    _depEngine = std::make_unique<dns::core::DeploymentEngine>(
        *_deEngine, *_veEngine, *_zrRepo, *_vrRepo, *_rrRepo, *_prRepo,
        *_drRepo, *_arRepo, nullptr, 10);
    _reEngine = std::make_unique<dns::core::RollbackEngine>(*_drRepo, *_rrRepo, *_arRepo);

    // Auth layer
    _amMiddleware = std::make_unique<dns::api::AuthMiddleware>(
        *_jsSigner, *_srRepo, *_akrRepo, *_urRepo, *_roleRepo, 3600, 300);
    _asService = std::make_unique<dns::security::AuthService>(
        *_urRepo, *_srRepo, *_roleRepo, *_jsSigner, 3600, 86400);

    // Routes
    _authRoutes = std::make_unique<dns::api::routes::AuthRoutes>(*_asService, *_amMiddleware, *_urRepo);
    _providerRoutes = std::make_unique<dns::api::routes::ProviderRoutes>(*_prRepo, *_amMiddleware);
    _viewRoutes = std::make_unique<dns::api::routes::ViewRoutes>(*_vrRepo, *_amMiddleware);
    _zoneRoutes = std::make_unique<dns::api::routes::ZoneRoutes>(*_zrRepo, *_amMiddleware, *_deEngine);
    _recordRoutes = std::make_unique<dns::api::routes::RecordRoutes>(
        *_rrRepo, *_zrRepo, *_arRepo, *_amMiddleware, *_deEngine, *_depEngine);
    _variableRoutes = std::make_unique<dns::api::routes::VariableRoutes>(*_varRepo, *_amMiddleware);
    _healthRoutes = std::make_unique<dns::api::routes::HealthRoutes>();
    _deploymentRoutes = std::make_unique<dns::api::routes::DeploymentRoutes>(
        *_drRepo, *_rrRepo, *_amMiddleware, *_reEngine);
    _auditRoutes = std::make_unique<dns::api::routes::AuditRoutes>(
        *_arRepo, *_amMiddleware, 365);

    // Setup routes
    _setupRoutes = std::make_unique<dns::api::routes::SetupRoutes>(
        *_cpPool, *_urRepo, *_jsSigner);

    // Crow app + server
    _app = std::make_unique<crow::SimpleApp>();
    _apiServer = std::make_unique<dns::api::ApiServer>(
        *_app, *_authRoutes, *_auditRoutes, *_deploymentRoutes, *_healthRoutes,
        *_providerRoutes, *_setupRoutes, *_viewRoutes, *_zoneRoutes, *_recordRoutes,
        *_variableRoutes);
    _apiServer->registerRoutes();
    _app->validate();

    // Clean DB
    {
      auto cg = _cpPool->checkout();
      pqxx::work txn(*cg);
      txn.exec("DELETE FROM records");
      txn.exec("DELETE FROM variables");
      txn.exec("DELETE FROM deployments");
      txn.exec("DELETE FROM zones");
      txn.exec("DELETE FROM view_providers");
      txn.exec("DELETE FROM views");
      txn.exec("DELETE FROM providers");
      txn.exec("DELETE FROM group_members");
      txn.exec("DELETE FROM sessions");
      txn.exec("DELETE FROM api_keys");
      txn.exec("DELETE FROM users");
      txn.exec("DELETE FROM groups");
      txn.commit();
    }

    // Create admin user and get a token
    std::string sHash = dns::security::CryptoService::hashPassword("admin123");
    int64_t iUserId = _urRepo->create("admin", "admin@test.com", sHash);

    {
      auto cg2 = _cpPool->checkout();
      pqxx::work txn2(*cg2);
      auto gResult = txn2.exec(
          "INSERT INTO groups (name) VALUES ('admins') RETURNING id");
      int64_t iGroupId = gResult.one_row()[0].as<int64_t>();
      auto rRole = txn2.exec("SELECT id FROM roles WHERE name = 'Admin'").one_row();
      int64_t iRoleId = rRole[0].as<int64_t>();
      txn2.exec("INSERT INTO group_members (user_id, group_id, role_id) VALUES ($1, $2, $3)",
                pqxx::params{iUserId, iGroupId, iRoleId});
      txn2.commit();
    }

    _sToken = _asService->authenticateLocal("admin", "admin123");
  }

  crow::response handle(const std::string& sMethod, const std::string& sUrl,
                        const std::string& sBody = "") {
    crow::request req;

    // Split URL into path and query string — Crow's trie matches only the path
    auto iQmark = sUrl.find('?');
    if (iQmark != std::string::npos) {
      req.url = sUrl.substr(0, iQmark);
      req.raw_url = sUrl;
      req.url_params = crow::query_string(sUrl);
    } else {
      req.url = sUrl;
      req.raw_url = sUrl;
    }

    req.body = sBody;
    req.add_header("Authorization", "Bearer " + _sToken);
    req.add_header("Content-Type", "application/json");

    if (sMethod == "GET") req.method = crow::HTTPMethod::GET;
    else if (sMethod == "POST") req.method = crow::HTTPMethod::POST;
    else if (sMethod == "PUT") req.method = crow::HTTPMethod::PUT;
    else if (sMethod == "DELETE") req.method = crow::HTTPMethod::DELETE;

    crow::response resp;
    _app->handle_full(req, resp);
    return resp;
  }

  std::string _sDbUrl;
  std::string _sToken;
  std::unique_ptr<ConnectionPool> _cpPool;
  std::unique_ptr<dns::security::CryptoService> _csService;
  std::unique_ptr<dns::security::HmacJwtSigner> _jsSigner;
  std::unique_ptr<dns::dal::UserRepository> _urRepo;
  std::unique_ptr<dns::dal::SessionRepository> _srRepo;
  std::unique_ptr<dns::dal::ApiKeyRepository> _akrRepo;
  std::unique_ptr<dns::dal::ProviderRepository> _prRepo;
  std::unique_ptr<dns::dal::ViewRepository> _vrRepo;
  std::unique_ptr<dns::dal::ZoneRepository> _zrRepo;
  std::unique_ptr<dns::dal::RecordRepository> _rrRepo;
  std::unique_ptr<dns::dal::VariableRepository> _varRepo;
  std::unique_ptr<dns::dal::DeploymentRepository> _drRepo;
  std::unique_ptr<dns::dal::AuditRepository> _arRepo;
  std::unique_ptr<dns::dal::RoleRepository> _roleRepo;
  std::unique_ptr<dns::core::VariableEngine> _veEngine;
  std::unique_ptr<dns::core::DiffEngine> _deEngine;
  std::unique_ptr<dns::core::DeploymentEngine> _depEngine;
  std::unique_ptr<dns::core::RollbackEngine> _reEngine;
  std::unique_ptr<dns::api::AuthMiddleware> _amMiddleware;
  std::unique_ptr<dns::security::AuthService> _asService;
  std::unique_ptr<dns::api::routes::AuthRoutes> _authRoutes;
  std::unique_ptr<dns::api::routes::HealthRoutes> _healthRoutes;
  std::unique_ptr<dns::api::routes::ProviderRoutes> _providerRoutes;
  std::unique_ptr<dns::api::routes::ViewRoutes> _viewRoutes;
  std::unique_ptr<dns::api::routes::ZoneRoutes> _zoneRoutes;
  std::unique_ptr<dns::api::routes::RecordRoutes> _recordRoutes;
  std::unique_ptr<dns::api::routes::VariableRoutes> _variableRoutes;
  std::unique_ptr<dns::api::routes::DeploymentRoutes> _deploymentRoutes;
  std::unique_ptr<dns::api::routes::AuditRoutes> _auditRoutes;
  std::unique_ptr<dns::api::routes::SetupRoutes> _setupRoutes;
  std::unique_ptr<crow::SimpleApp> _app;
  std::unique_ptr<dns::api::ApiServer> _apiServer;
};

TEST_F(CrudRoutesTest, ProviderCrud) {
  // Create
  auto resp = handle("POST", "/api/v1/providers",
                     R"({"name":"pdns","type":"powerdns","api_endpoint":"http://pdns:8081","token":"key"})");
  EXPECT_EQ(resp.code, 201);
  auto jResp = nlohmann::json::parse(resp.body);
  int64_t iId = jResp["id"].get<int64_t>();

  // Get
  resp = handle("GET", "/api/v1/providers/" + std::to_string(iId));
  EXPECT_EQ(resp.code, 200);
  jResp = nlohmann::json::parse(resp.body);
  EXPECT_EQ(jResp["name"], "pdns");
  EXPECT_EQ(jResp["token"], "key");

  // List (no token in list)
  resp = handle("GET", "/api/v1/providers");
  EXPECT_EQ(resp.code, 200);
  jResp = nlohmann::json::parse(resp.body);
  ASSERT_EQ(jResp.size(), 1u);
  EXPECT_FALSE(jResp[0].contains("token"));

  // Update
  resp = handle("PUT", "/api/v1/providers/" + std::to_string(iId),
                R"({"name":"renamed","api_endpoint":"http://new:8081"})");
  EXPECT_EQ(resp.code, 200);

  // Delete
  resp = handle("DELETE", "/api/v1/providers/" + std::to_string(iId));
  EXPECT_EQ(resp.code, 200);

  // Verify deleted
  resp = handle("GET", "/api/v1/providers/" + std::to_string(iId));
  EXPECT_EQ(resp.code, 404);
}

TEST_F(CrudRoutesTest, ViewCrudWithProviders) {
  // Create view
  auto resp = handle("POST", "/api/v1/views", R"({"name":"internal","description":"LAN"})");
  EXPECT_EQ(resp.code, 201);
  int64_t iViewId = nlohmann::json::parse(resp.body)["id"].get<int64_t>();

  // Create provider for attach test
  resp = handle("POST", "/api/v1/providers",
                R"({"name":"p1","type":"powerdns","api_endpoint":"http://p1:8081","token":"k"})");
  int64_t iProvId = nlohmann::json::parse(resp.body)["id"].get<int64_t>();

  // Attach provider
  resp = handle("POST", "/api/v1/views/" + std::to_string(iViewId) +
                "/providers/" + std::to_string(iProvId));
  EXPECT_EQ(resp.code, 200);

  // Get with providers
  resp = handle("GET", "/api/v1/views/" + std::to_string(iViewId));
  EXPECT_EQ(resp.code, 200);
  auto j = nlohmann::json::parse(resp.body);
  EXPECT_EQ(j["provider_ids"].size(), 1u);

  // Detach
  resp = handle("DELETE", "/api/v1/views/" + std::to_string(iViewId) +
                "/providers/" + std::to_string(iProvId));
  EXPECT_EQ(resp.code, 200);

  // Delete view
  resp = handle("DELETE", "/api/v1/views/" + std::to_string(iViewId));
  EXPECT_EQ(resp.code, 200);
}

TEST_F(CrudRoutesTest, ZoneCrud) {
  // Create view first
  auto resp = handle("POST", "/api/v1/views", R"({"name":"z-view","description":""})");
  int64_t iViewId = nlohmann::json::parse(resp.body)["id"].get<int64_t>();

  // Create zone
  resp = handle("POST", "/api/v1/zones",
                R"({"name":"example.com","view_id":)" + std::to_string(iViewId) + "}");
  EXPECT_EQ(resp.code, 201);
  int64_t iZoneId = nlohmann::json::parse(resp.body)["id"].get<int64_t>();

  // List by view
  resp = handle("GET", "/api/v1/zones?view_id=" + std::to_string(iViewId));
  EXPECT_EQ(resp.code, 200);
  EXPECT_EQ(nlohmann::json::parse(resp.body).size(), 1u);

  // Update
  resp = handle("PUT", "/api/v1/zones/" + std::to_string(iZoneId),
                R"({"name":"example.com","deployment_retention":5})");
  EXPECT_EQ(resp.code, 200);

  // Delete
  resp = handle("DELETE", "/api/v1/zones/" + std::to_string(iZoneId));
  EXPECT_EQ(resp.code, 200);
}

TEST_F(CrudRoutesTest, RecordCrud) {
  auto resp = handle("POST", "/api/v1/views", R"({"name":"r-view","description":""})");
  int64_t iViewId = nlohmann::json::parse(resp.body)["id"].get<int64_t>();

  resp = handle("POST", "/api/v1/zones",
                R"({"name":"rec.com","view_id":)" + std::to_string(iViewId) + "}");
  int64_t iZoneId = nlohmann::json::parse(resp.body)["id"].get<int64_t>();

  // Create record
  resp = handle("POST", "/api/v1/zones/" + std::to_string(iZoneId) + "/records",
                R"({"name":"www","type":"A","ttl":300,"value_template":"{{LB_VIP}}","priority":0})");
  EXPECT_EQ(resp.code, 201);
  int64_t iRecId = nlohmann::json::parse(resp.body)["id"].get<int64_t>();

  // List by zone
  resp = handle("GET", "/api/v1/zones/" + std::to_string(iZoneId) + "/records");
  EXPECT_EQ(resp.code, 200);
  EXPECT_EQ(nlohmann::json::parse(resp.body).size(), 1u);

  // Update
  resp = handle("PUT", "/api/v1/zones/" + std::to_string(iZoneId) +
                "/records/" + std::to_string(iRecId),
                R"({"name":"www","type":"A","ttl":600,"value_template":"1.2.3.4","priority":0})");
  EXPECT_EQ(resp.code, 200);

  // Delete
  resp = handle("DELETE", "/api/v1/zones/" + std::to_string(iZoneId) +
                "/records/" + std::to_string(iRecId));
  EXPECT_EQ(resp.code, 200);
}

TEST_F(CrudRoutesTest, VariableCrud) {
  // Create global variable
  auto resp = handle("POST", "/api/v1/variables",
                     R"({"name":"LB_VIP","value":"10.0.0.1","type":"ipv4","scope":"global"})");
  EXPECT_EQ(resp.code, 201);
  int64_t iVarId = nlohmann::json::parse(resp.body)["id"].get<int64_t>();

  // List all
  resp = handle("GET", "/api/v1/variables");
  EXPECT_EQ(resp.code, 200);
  EXPECT_GE(nlohmann::json::parse(resp.body).size(), 1u);

  // List by scope
  resp = handle("GET", "/api/v1/variables?scope=global");
  EXPECT_EQ(resp.code, 200);
  EXPECT_GE(nlohmann::json::parse(resp.body).size(), 1u);

  // Update
  resp = handle("PUT", "/api/v1/variables/" + std::to_string(iVarId),
                R"({"value":"10.0.0.2"})");
  EXPECT_EQ(resp.code, 200);

  // Delete
  resp = handle("DELETE", "/api/v1/variables/" + std::to_string(iVarId));
  EXPECT_EQ(resp.code, 200);
}

TEST_F(CrudRoutesTest, UnauthorizedReturns401) {
  crow::request req;
  req.url = "/api/v1/providers";
  req.method = crow::HTTPMethod::GET;
  // No auth headers

  crow::response resp;
  _app->handle_full(req, resp);
  EXPECT_EQ(resp.code, 401);
}
