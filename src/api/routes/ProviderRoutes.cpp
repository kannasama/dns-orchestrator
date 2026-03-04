#include "api/routes/ProviderRoutes.hpp"

#include "api/AuthMiddleware.hpp"
#include "common/Errors.hpp"
#include "dal/ProviderRepository.hpp"

#include <nlohmann/json.hpp>

namespace dns::api::routes {

ProviderRoutes::ProviderRoutes(dns::dal::ProviderRepository& prRepo,
                               const dns::api::AuthMiddleware& amMiddleware)
    : _prRepo(prRepo), _amMiddleware(amMiddleware) {}

ProviderRoutes::~ProviderRoutes() = default;

namespace {

void requireRole(const common::RequestContext& rcCtx, const std::string& sMinRole) {
  if (sMinRole == "admin" && rcCtx.sRole != "admin") {
    throw common::AuthorizationError("INSUFFICIENT_ROLE",
                                     "Admin role required");
  }
  if (sMinRole == "operator" && rcCtx.sRole == "viewer") {
    throw common::AuthorizationError("INSUFFICIENT_ROLE",
                                     "Operator or admin role required");
  }
}

common::RequestContext authenticate(const dns::api::AuthMiddleware& am,
                                    const crow::request& req) {
  return am.authenticate(req.get_header_value("Authorization"),
                         req.get_header_value("X-API-Key"));
}

crow::response jsonResponse(int iStatus, const nlohmann::json& j) {
  crow::response resp(iStatus, j.dump(2));
  resp.set_header("Content-Type", "application/json");
  return resp;
}

crow::response errorResponse(const common::AppError& e) {
  nlohmann::json jErr = {{"error", e._sErrorCode}, {"message", e.what()}};
  return crow::response(e._iHttpStatus, jErr.dump(2));
}

}  // namespace

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

          if (sName.empty() || sType.empty() || sEndpoint.empty() || sToken.empty()) {
            throw common::ValidationError("MISSING_FIELDS",
                                          "name, type, api_endpoint, and token are required");
          }

          int64_t iId = _prRepo.create(sName, sType, sEndpoint, sToken);
          return jsonResponse(201, {{"id", iId}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        } catch (const nlohmann::json::exception&) {
          nlohmann::json jErr = {{"error", "invalid_json"},
                                 {"message", "Invalid JSON body"}};
          return crow::response(400, jErr.dump(2));
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

          if (sName.empty() || sEndpoint.empty()) {
            throw common::ValidationError("MISSING_FIELDS",
                                          "name and api_endpoint are required");
          }

          std::optional<std::string> oToken;
          if (jBody.contains("token") && !jBody["token"].is_null()) {
            oToken = jBody["token"].get<std::string>();
          }

          _prRepo.update(iId, sName, sEndpoint, oToken);
          return jsonResponse(200, {{"message", "Provider updated"}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        } catch (const nlohmann::json::exception&) {
          nlohmann::json jErr = {{"error", "invalid_json"},
                                 {"message", "Invalid JSON body"}};
          return crow::response(400, jErr.dump(2));
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
