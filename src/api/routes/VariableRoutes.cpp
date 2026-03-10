#include "api/routes/VariableRoutes.hpp"

#include "api/AuthMiddleware.hpp"
#include "api/RequestValidator.hpp"
#include "api/RouteHelpers.hpp"
#include "common/Errors.hpp"
#include "common/Permissions.hpp"
#include "dal/VariableRepository.hpp"

#include <nlohmann/json.hpp>

namespace dns::api::routes {
using namespace dns::common;

VariableRoutes::VariableRoutes(dns::dal::VariableRepository& varRepo,
                               const dns::api::AuthMiddleware& amMiddleware)
    : _varRepo(varRepo), _amMiddleware(amMiddleware) {}

VariableRoutes::~VariableRoutes() = default;

namespace {

nlohmann::json variableRowToJson(const dns::dal::VariableRow& row) {
  nlohmann::json j = {
      {"id", row.iId},
      {"name", row.sName},
      {"value", row.sValue},
      {"type", row.sType},
      {"scope", row.sScope},
      {"created_at", std::chrono::duration_cast<std::chrono::seconds>(
                         row.tpCreatedAt.time_since_epoch())
                         .count()},
      {"updated_at", std::chrono::duration_cast<std::chrono::seconds>(
                         row.tpUpdatedAt.time_since_epoch())
                         .count()},
  };
  if (row.oZoneId.has_value()) {
    j["zone_id"] = *row.oZoneId;
  } else {
    j["zone_id"] = nullptr;
  }
  return j;
}

}  // namespace

void VariableRoutes::registerRoutes(crow::SimpleApp& app) {
  // GET /api/v1/variables
  CROW_ROUTE(app, "/api/v1/variables").methods("GET"_method)(
      [this](const crow::request& req) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kVariablesView);

          auto sScope = req.url_params.get("scope");
          auto sZoneId = req.url_params.get("zone_id");

          std::vector<dns::dal::VariableRow> vRows;
          if (sZoneId) {
            vRows = _varRepo.listByZoneId(std::stoll(sZoneId));
          } else if (sScope) {
            vRows = _varRepo.listByScope(sScope);
          } else {
            vRows = _varRepo.listAll();
          }

          nlohmann::json jArr = nlohmann::json::array();
          for (const auto& row : vRows) {
            jArr.push_back(variableRowToJson(row));
          }
          return jsonResponse(200, jArr);
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });

  // POST /api/v1/variables
  CROW_ROUTE(app, "/api/v1/variables").methods("POST"_method)(
      [this](const crow::request& req) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kVariablesCreate);

          auto jBody = nlohmann::json::parse(req.body);
          std::string sName = jBody.value("name", "");
          std::string sValue = jBody.value("value", "");
          std::string sType = jBody.value("type", "");
          std::string sScope = jBody.value("scope", "global");

          RequestValidator::validateVariableName(sName);
          RequestValidator::validateVariableValue(sValue);
          RequestValidator::validateRequired(sType, "type");

          std::optional<int64_t> oZoneId;
          if (jBody.contains("zone_id") && !jBody["zone_id"].is_null()) {
            oZoneId = jBody["zone_id"].get<int64_t>();
          }

          int64_t iId = _varRepo.create(sName, sValue, sType, sScope, oZoneId);
          return jsonResponse(201, {{"id", iId}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        } catch (const nlohmann::json::exception&) {
          return invalidJsonResponse();
        }
      });

  // GET /api/v1/variables/<int>
  CROW_ROUTE(app, "/api/v1/variables/<int>").methods("GET"_method)(
      [this](const crow::request& req, int iId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kVariablesView);

          auto oRow = _varRepo.findById(iId);
          if (!oRow.has_value()) {
            throw common::NotFoundError("VARIABLE_NOT_FOUND", "Variable not found");
          }
          return jsonResponse(200, variableRowToJson(*oRow));
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });

  // PUT /api/v1/variables/<int>
  CROW_ROUTE(app, "/api/v1/variables/<int>").methods("PUT"_method)(
      [this](const crow::request& req, int iId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kVariablesEdit);

          auto jBody = nlohmann::json::parse(req.body);
          std::string sValue = jBody.value("value", "");

          RequestValidator::validateVariableValue(sValue);

          _varRepo.update(iId, sValue);
          return jsonResponse(200, {{"message", "Variable updated"}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        } catch (const nlohmann::json::exception&) {
          return invalidJsonResponse();
        }
      });

  // DELETE /api/v1/variables/<int>
  CROW_ROUTE(app, "/api/v1/variables/<int>").methods("DELETE"_method)(
      [this](const crow::request& req, int iId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kVariablesDelete);

          _varRepo.deleteById(iId);
          return jsonResponse(200, {{"message", "Variable deleted"}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });
}

}  // namespace dns::api::routes
