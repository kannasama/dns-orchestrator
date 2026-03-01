#include "api/routes/AuthRoutes.hpp"

#include "api/AuthMiddleware.hpp"
#include "common/Errors.hpp"
#include "security/AuthService.hpp"

#include <nlohmann/json.hpp>

namespace dns::api::routes {

AuthRoutes::AuthRoutes(dns::security::AuthService& asService,
                       const dns::api::AuthMiddleware& amMiddleware)
    : _asService(asService), _amMiddleware(amMiddleware) {}

AuthRoutes::~AuthRoutes() = default;

void AuthRoutes::registerRoutes(crow::SimpleApp& app) {
  // POST /api/v1/auth/local/login
  CROW_ROUTE(app, "/api/v1/auth/local/login").methods("POST"_method)(
      [this](const crow::request& req) -> crow::response {
        try {
          auto jBody = nlohmann::json::parse(req.body);
          std::string sUsername = jBody.value("username", "");
          std::string sPassword = jBody.value("password", "");

          if (sUsername.empty() || sPassword.empty()) {
            nlohmann::json jErr = {{"error", "validation_error"},
                                   {"message", "username and password are required"}};
            return crow::response(400, jErr.dump(2));
          }

          std::string sToken = _asService.authenticateLocal(sUsername, sPassword);

          nlohmann::json jResp = {{"token", sToken}};
          crow::response resp(200, jResp.dump(2));
          resp.set_header("Content-Type", "application/json");
          return resp;
        } catch (const common::AppError& e) {
          nlohmann::json jErr = {{"error", e._sErrorCode}, {"message", e.what()}};
          return crow::response(e._iHttpStatus, jErr.dump(2));
        } catch (const nlohmann::json::exception&) {
          nlohmann::json jErr = {{"error", "invalid_json"}, {"message", "Invalid JSON body"}};
          return crow::response(400, jErr.dump(2));
        }
      });

  // POST /api/v1/auth/local/logout
  CROW_ROUTE(app, "/api/v1/auth/local/logout").methods("POST"_method)(
      [this](const crow::request& req) -> crow::response {
        try {
          std::string sAuth = req.get_header_value("Authorization");
          std::string sApiKey = req.get_header_value("X-API-Key");

          // Authenticate first to verify the token is valid
          _amMiddleware.authenticate(sAuth, sApiKey);

          nlohmann::json jResp = {{"message", "Logged out successfully"}};
          crow::response resp(200, jResp.dump(2));
          resp.set_header("Content-Type", "application/json");
          return resp;
        } catch (const common::AppError& e) {
          nlohmann::json jErr = {{"error", e._sErrorCode}, {"message", e.what()}};
          return crow::response(e._iHttpStatus, jErr.dump(2));
        }
      });

  // GET /api/v1/auth/me
  CROW_ROUTE(app, "/api/v1/auth/me").methods("GET"_method)(
      [this](const crow::request& req) -> crow::response {
        try {
          std::string sAuth = req.get_header_value("Authorization");
          std::string sApiKey = req.get_header_value("X-API-Key");

          auto rcCtx = _amMiddleware.authenticate(sAuth, sApiKey);

          nlohmann::json jResp = {
              {"user_id", rcCtx.iUserId},
              {"username", rcCtx.sUsername},
              {"role", rcCtx.sRole},
              {"auth_method", rcCtx.sAuthMethod},
          };
          crow::response resp(200, jResp.dump(2));
          resp.set_header("Content-Type", "application/json");
          return resp;
        } catch (const common::AppError& e) {
          nlohmann::json jErr = {{"error", e._sErrorCode}, {"message", e.what()}};
          return crow::response(e._iHttpStatus, jErr.dump(2));
        }
      });
}

}  // namespace dns::api::routes
