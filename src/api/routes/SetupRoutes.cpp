#include "api/routes/SetupRoutes.hpp"

#include "api/RequestValidator.hpp"
#include "api/RouteHelpers.hpp"
#include "common/Errors.hpp"
#include "dal/ConnectionPool.hpp"
#include "dal/UserRepository.hpp"
#include "security/CryptoService.hpp"
#include "security/IJwtSigner.hpp"

#include <nlohmann/json.hpp>
#include <pqxx/pqxx>
#include <spdlog/spdlog.h>

namespace dns::api::routes {

SetupRoutes::SetupRoutes(dns::dal::ConnectionPool& cpPool,
                         dns::dal::UserRepository& urRepo,
                         const dns::security::IJwtSigner& jsSigner)
    : _cpPool(cpPool), _urRepo(urRepo), _jsSigner(jsSigner) {}

SetupRoutes::~SetupRoutes() = default;

void SetupRoutes::setSetupToken(const std::string& sToken) {
  _sSetupToken = sToken;
}

bool SetupRoutes::isSetupCompleted() const {
  return _bSetupCompleted.load();
}

void SetupRoutes::loadSetupState() {
  try {
    auto cgConn = _cpPool.checkout();
    pqxx::work txn(*cgConn);
    auto row = txn.exec(
        "SELECT value FROM system_config WHERE key = 'setup_completed'");
    if (!row.empty() && row[0][0].as<std::string>() == "true") {
      _bSetupCompleted = true;
    }
    txn.commit();
  } catch (const std::exception& e) {
    spdlog::warn("SetupRoutes::loadSetupState failed: {}", e.what());
  }
}

void SetupRoutes::registerRoutes(crow::SimpleApp& app) {
  // GET /api/v1/setup/status
  CROW_ROUTE(app, "/api/v1/setup/status").methods("GET"_method)(
      [this](const crow::request& /*req*/) -> crow::response {
        bool bCompleted = _bSetupCompleted.load();
        return jsonResponse(200, {{"setup_required", !bCompleted}});
      });

  // POST /api/v1/setup
  CROW_ROUTE(app, "/api/v1/setup").methods("POST"_method)(
      [this](const crow::request& req) -> crow::response {
        try {
          // 1. Check if setup is already completed
          if (_bSetupCompleted.load()) {
            return jsonResponse(403, {{"error", "SETUP_COMPLETED"},
                                      {"message", "Initial setup has already been completed"}});
          }

          auto jBody = nlohmann::json::parse(req.body);
          std::string sSetupToken = jBody.value("setup_token", "");
          std::string sUsername = jBody.value("username", "");
          std::string sEmail = jBody.value("email", "");
          std::string sPassword = jBody.value("password", "");

          // 2. Validate setup JWT token
          auto jPayload = _jsSigner.verify(sSetupToken);
          if (jPayload.value("purpose", "") != "setup") {
            throw common::AuthenticationError("invalid_token", "Invalid setup token");
          }

          // 3. Validate input fields
          RequestValidator::validateUsername(sUsername);
          RequestValidator::validatePassword(sPassword);
          if (sEmail.empty()) {
            throw common::ValidationError("INVALID_EMAIL", "Email is required");
          }

          // 4. Transactional setup
          auto cgConn = _cpPool.checkout();
          pqxx::work txn(*cgConn);

          // 4a. Check system_config for setup_completed
          auto rConfig = txn.exec(
              "SELECT value FROM system_config WHERE key = 'setup_completed'");
          if (!rConfig.empty() && rConfig[0][0].as<std::string>() == "true") {
            txn.abort();
            return jsonResponse(403, {{"error", "SETUP_COMPLETED"},
                                      {"message", "Initial setup has already been completed"}});
          }

          // 4b. Check no users exist
          auto rCount = txn.exec("SELECT COUNT(*) FROM users");
          if (rCount[0][0].as<int64_t>() > 0) {
            txn.abort();
            return jsonResponse(403, {{"error", "SETUP_COMPLETED"},
                                      {"message", "Users already exist"}});
          }

          // 4c. Hash password
          std::string sPasswordHash = security::CryptoService::hashPassword(sPassword);

          // 4d. Insert user
          auto rUser = txn.exec(
              "INSERT INTO users (username, email, password_hash, auth_method) "
              "VALUES ($1, $2, $3, 'local') RETURNING id",
              pqxx::params{sUsername, sEmail, sPasswordHash});
          int64_t iUserId = rUser[0][0].as<int64_t>();

          // 4e. Create Admins group
          auto rGroup = txn.exec(
              "INSERT INTO groups (name, description) "
              "VALUES ('Admins', 'System administrators') RETURNING id");
          int64_t iGroupId = rGroup[0][0].as<int64_t>();

          // 4f. Add user to group with Admin role
          auto rRole = txn.exec("SELECT id FROM roles WHERE name = 'Admin'");
          int64_t iRoleId = rRole[0][0].as<int64_t>();
          txn.exec(
              "INSERT INTO group_members (user_id, group_id, role_id) VALUES ($1, $2, $3)",
              pqxx::params{iUserId, iGroupId, iRoleId});

          // 4g. Mark setup complete
          txn.exec(
              "INSERT INTO system_config (key, value) VALUES ('setup_completed', 'true') "
              "ON CONFLICT (key) DO UPDATE SET value = 'true'");

          // 4h. Commit transaction
          txn.commit();

          // 5. Update cached flag
          _bSetupCompleted = true;

          // 6. Return success
          return jsonResponse(200, {{"message", "Setup complete"},
                                    {"user_id", iUserId}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        } catch (const nlohmann::json::exception&) {
          return invalidJsonResponse();
        }
      });
}

}  // namespace dns::api::routes
