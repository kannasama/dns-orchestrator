#include "api/routes/VariableRoutes.hpp"

#include "api/AuthMiddleware.hpp"
#include "common/Errors.hpp"
#include "dal/VariableRepository.hpp"

#include <nlohmann/json.hpp>

namespace dns::api::routes {

VariableRoutes::VariableRoutes(dns::dal::VariableRepository& varRepo,
                               const dns::api::AuthMiddleware& amMiddleware)
    : _varRepo(varRepo), _amMiddleware(amMiddleware) {}
VariableRoutes::~VariableRoutes() = default;

void VariableRoutes::registerRoutes(crow::SimpleApp& app) {
  // GET /api/v1/variables
  CROW_ROUTE(app, "/api/v1/variables").methods("GET"_method)(
      [this](const crow::request& req) -> crow::response {
        try {
          std::string sAuth = req.get_header_value("Authorization");
          std::string sApiKey = req.get_header_value("X-API-Key");
          _amMiddleware.authenticate(sAuth, sApiKey);

          std::optional<std::string> oScope;
          std::optional<int64_t> oZoneId;
          auto* pScope = req.url_params.get("scope");
          if (pScope) oScope = std::string(pScope);
          auto* pZoneId = req.url_params.get("zone_id");
          if (pZoneId) oZoneId = std::stoll(pZoneId);

          auto vVars = _varRepo.list(oScope, oZoneId);
          nlohmann::json jArr = nlohmann::json::array();
          for (const auto& v : vVars) {
            nlohmann::json jVar = {
                {"id", v.iId},     {"name", v.sName},
                {"value", v.sValue}, {"type", v.sType},
                {"scope", v.sScope}, {"created_at", v.sCreatedAt},
                {"updated_at", v.sUpdatedAt}};
            if (v.oZoneId.has_value()) {
              jVar["zone_id"] = *v.oZoneId;
            } else {
              jVar["zone_id"] = nullptr;
            }
            jArr.push_back(jVar);
          }
          crow::response resp(200, jArr.dump(2));
          resp.set_header("Content-Type", "application/json");
          return resp;
        } catch (const common::AppError& e) {
          nlohmann::json jErr = {{"error", e._sErrorCode},
                                 {"message", e.what()}};
          return crow::response(e._iHttpStatus, jErr.dump(2));
        }
      });

  // POST /api/v1/variables
  CROW_ROUTE(app, "/api/v1/variables").methods("POST"_method)(
      [this](const crow::request& req) -> crow::response {
        try {
          std::string sAuth = req.get_header_value("Authorization");
          std::string sApiKey = req.get_header_value("X-API-Key");
          auto rcCtx = _amMiddleware.authenticate(sAuth, sApiKey);
          if (rcCtx.sRole == "viewer") {
            throw common::AuthorizationError("insufficient_role",
                                             "Operator role required");
          }

          auto jBody = nlohmann::json::parse(req.body);
          std::string sName = jBody.value("name", "");
          std::string sValue = jBody.value("value", "");
          std::string sType = jBody.value("type", "");
          std::string sScope = jBody.value("scope", "global");

          if (sName.empty() || sValue.empty() || sType.empty()) {
            throw common::ValidationError(
                "missing_fields", "name, value, and type are required");
          }

          std::optional<int64_t> oZoneId;
          if (jBody.contains("zone_id") && !jBody["zone_id"].is_null()) {
            oZoneId = jBody["zone_id"].get<int64_t>();
          }

          int64_t iId =
              _varRepo.create(sName, sValue, sType, sScope, oZoneId);
          nlohmann::json jResp = {{"id", iId},       {"name", sName},
                                  {"value", sValue}, {"type", sType},
                                  {"scope", sScope}};
          if (oZoneId.has_value()) {
            jResp["zone_id"] = *oZoneId;
          }
          crow::response resp(201, jResp.dump(2));
          resp.set_header("Content-Type", "application/json");
          return resp;
        } catch (const common::AppError& e) {
          nlohmann::json jErr = {{"error", e._sErrorCode},
                                 {"message", e.what()}};
          return crow::response(e._iHttpStatus, jErr.dump(2));
        } catch (const nlohmann::json::exception&) {
          nlohmann::json jErr = {{"error", "invalid_json"},
                                 {"message", "Invalid JSON body"}};
          return crow::response(400, jErr.dump(2));
        }
      });

  // GET /api/v1/variables/<int>
  CROW_ROUTE(app, "/api/v1/variables/<int>").methods("GET"_method)(
      [this](const crow::request& req, int iId) -> crow::response {
        try {
          std::string sAuth = req.get_header_value("Authorization");
          std::string sApiKey = req.get_header_value("X-API-Key");
          _amMiddleware.authenticate(sAuth, sApiKey);

          auto oVar = _varRepo.findById(iId);
          if (!oVar.has_value()) {
            throw common::NotFoundError("variable_not_found",
                                        "Variable not found");
          }

          nlohmann::json jResp = {
              {"id", oVar->iId},     {"name", oVar->sName},
              {"value", oVar->sValue}, {"type", oVar->sType},
              {"scope", oVar->sScope}, {"created_at", oVar->sCreatedAt},
              {"updated_at", oVar->sUpdatedAt}};
          if (oVar->oZoneId.has_value()) {
            jResp["zone_id"] = *oVar->oZoneId;
          } else {
            jResp["zone_id"] = nullptr;
          }
          crow::response resp(200, jResp.dump(2));
          resp.set_header("Content-Type", "application/json");
          return resp;
        } catch (const common::AppError& e) {
          nlohmann::json jErr = {{"error", e._sErrorCode},
                                 {"message", e.what()}};
          return crow::response(e._iHttpStatus, jErr.dump(2));
        }
      });

  // PUT /api/v1/variables/<int>
  CROW_ROUTE(app, "/api/v1/variables/<int>").methods("PUT"_method)(
      [this](const crow::request& req, int iId) -> crow::response {
        try {
          std::string sAuth = req.get_header_value("Authorization");
          std::string sApiKey = req.get_header_value("X-API-Key");
          auto rcCtx = _amMiddleware.authenticate(sAuth, sApiKey);
          if (rcCtx.sRole == "viewer") {
            throw common::AuthorizationError("insufficient_role",
                                             "Operator role required");
          }

          auto jBody = nlohmann::json::parse(req.body);
          std::string sName = jBody.value("name", "");
          std::string sValue = jBody.value("value", "");
          std::string sType = jBody.value("type", "");

          if (sName.empty() || sValue.empty() || sType.empty()) {
            throw common::ValidationError(
                "missing_fields", "name, value, and type are required");
          }

          _varRepo.update(iId, sName, sValue, sType);
          nlohmann::json jResp = {{"id", iId}, {"name", sName},
                                  {"value", sValue}, {"type", sType}};
          crow::response resp(200, jResp.dump(2));
          resp.set_header("Content-Type", "application/json");
          return resp;
        } catch (const common::AppError& e) {
          nlohmann::json jErr = {{"error", e._sErrorCode},
                                 {"message", e.what()}};
          return crow::response(e._iHttpStatus, jErr.dump(2));
        } catch (const nlohmann::json::exception&) {
          nlohmann::json jErr = {{"error", "invalid_json"},
                                 {"message", "Invalid JSON body"}};
          return crow::response(400, jErr.dump(2));
        }
      });

  // DELETE /api/v1/variables/<int>
  CROW_ROUTE(app, "/api/v1/variables/<int>").methods("DELETE"_method)(
      [this](const crow::request& req, int iId) -> crow::response {
        try {
          std::string sAuth = req.get_header_value("Authorization");
          std::string sApiKey = req.get_header_value("X-API-Key");
          auto rcCtx = _amMiddleware.authenticate(sAuth, sApiKey);
          if (rcCtx.sRole == "viewer") {
            throw common::AuthorizationError("insufficient_role",
                                             "Operator role required");
          }

          _varRepo.deleteById(iId);
          return crow::response(204);
        } catch (const common::AppError& e) {
          nlohmann::json jErr = {{"error", e._sErrorCode},
                                 {"message", e.what()}};
          return crow::response(e._iHttpStatus, jErr.dump(2));
        }
      });
}

}  // namespace dns::api::routes
