#include "api/routes/ProviderRoutes.hpp"

#include "api/AuthMiddleware.hpp"
#include "api/RequestValidator.hpp"
#include "api/RouteHelpers.hpp"
#include "common/Errors.hpp"
#include "dal/ProviderRepository.hpp"

#include <nlohmann/json.hpp>

namespace dns::api::routes {

ProviderRoutes::ProviderRoutes(dns::dal::ProviderRepository& prRepo,
                               const dns::api::AuthMiddleware& amMiddleware)
    : _prRepo(prRepo), _amMiddleware(amMiddleware) {}

ProviderRoutes::~ProviderRoutes() = default;

void ProviderRoutes::registerRoutes(crow::SimpleApp& app) {
  // GET /api/v1/providers
  CROW_ROUTE(app, "/api/v1/providers").methods("GET"_method)(
      [this](const crow::request& req) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requireRole(rcCtx, "viewer");

          auto vRows = _prRepo.listAll();
          nlohmann::json jArr = nlohmann::json::array();
          for (const auto& row : vRows) {
            jArr.push_back({
                {"id", row.iId},
                {"name", row.sName},
                {"type", row.sType},
                {"api_endpoint", row.sApiEndpoint},
                {"config", row.jConfig},
                {"created_at", std::chrono::duration_cast<std::chrono::seconds>(
                                   row.tpCreatedAt.time_since_epoch())
                                   .count()},
                {"updated_at", std::chrono::duration_cast<std::chrono::seconds>(
                                   row.tpUpdatedAt.time_since_epoch())
                                   .count()},
            });
          }
          return jsonResponse(200, jArr);
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });

  // POST /api/v1/providers
  CROW_ROUTE(app, "/api/v1/providers").methods("POST"_method)(
      [this](const crow::request& req) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requireRole(rcCtx, "admin");

          auto jBody = nlohmann::json::parse(req.body);
          std::string sName = jBody.value("name", "");
          std::string sType = jBody.value("type", "");
          std::string sEndpoint = jBody.value("api_endpoint", "");
          std::string sToken = jBody.value("token", "");

          RequestValidator::validateProviderName(sName);
          RequestValidator::validateProviderType(sType);
          RequestValidator::validateRequired(sEndpoint, "api_endpoint");
          RequestValidator::validateRequired(sToken, "token");

          nlohmann::json jConfig = nlohmann::json::object();
          if (jBody.contains("config") && jBody["config"].is_object()) {
            jConfig = jBody["config"];
          }

          int64_t iId = _prRepo.create(sName, sType, sEndpoint, sToken, jConfig);
          return jsonResponse(201, {{"id", iId}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        } catch (const nlohmann::json::exception&) {
          return invalidJsonResponse();
        }
      });

  // GET /api/v1/providers/<int>
  CROW_ROUTE(app, "/api/v1/providers/<int>").methods("GET"_method)(
      [this](const crow::request& req, int iId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requireRole(rcCtx, "viewer");

          auto oRow = _prRepo.findById(iId);
          if (!oRow.has_value()) {
            throw common::NotFoundError("PROVIDER_NOT_FOUND", "Provider not found");
          }

          nlohmann::json jResp = {
              {"id", oRow->iId},
              {"name", oRow->sName},
              {"type", oRow->sType},
              {"api_endpoint", oRow->sApiEndpoint},
              {"token", oRow->sDecryptedToken},
              {"config", oRow->jConfig},
              {"created_at", std::chrono::duration_cast<std::chrono::seconds>(
                                 oRow->tpCreatedAt.time_since_epoch())
                                 .count()},
              {"updated_at", std::chrono::duration_cast<std::chrono::seconds>(
                                 oRow->tpUpdatedAt.time_since_epoch())
                                 .count()},
          };
          return jsonResponse(200, jResp);
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });

  // PUT /api/v1/providers/<int>
  CROW_ROUTE(app, "/api/v1/providers/<int>").methods("PUT"_method)(
      [this](const crow::request& req, int iId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requireRole(rcCtx, "admin");

          auto jBody = nlohmann::json::parse(req.body);
          std::string sName = jBody.value("name", "");
          std::string sEndpoint = jBody.value("api_endpoint", "");

          RequestValidator::validateProviderName(sName);
          RequestValidator::validateRequired(sEndpoint, "api_endpoint");

          std::optional<std::string> oToken;
          if (jBody.contains("token") && !jBody["token"].is_null()) {
            oToken = jBody["token"].get<std::string>();
          }

          std::optional<nlohmann::json> oConfig;
          if (jBody.contains("config") && jBody["config"].is_object()) {
            oConfig = jBody["config"];
          }

          _prRepo.update(iId, sName, sEndpoint, oToken, oConfig);
          return jsonResponse(200, {{"message", "Provider updated"}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        } catch (const nlohmann::json::exception&) {
          return invalidJsonResponse();
        }
      });

  // DELETE /api/v1/providers/<int>
  CROW_ROUTE(app, "/api/v1/providers/<int>").methods("DELETE"_method)(
      [this](const crow::request& req, int iId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requireRole(rcCtx, "admin");

          _prRepo.deleteById(iId);
          return jsonResponse(200, {{"message", "Provider deleted"}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });
}

}  // namespace dns::api::routes
