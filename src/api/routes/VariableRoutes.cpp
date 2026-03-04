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

namespace {

void requireRole(const common::RequestContext& rcCtx, const std::string& sMinRole) {
  if (sMinRole == "admin" && rcCtx.sRole != "admin") {
    throw common::AuthorizationError("INSUFFICIENT_ROLE", "Admin role required");
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
          requireRole(rcCtx, "viewer");

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
          requireRole(rcCtx, "operator");

          auto jBody = nlohmann::json::parse(req.body);
          std::string sName = jBody.value("name", "");
          std::string sValue = jBody.value("value", "");
          std::string sType = jBody.value("type", "");
          std::string sScope = jBody.value("scope", "global");

          if (sName.empty() || sValue.empty() || sType.empty()) {
            throw common::ValidationError("MISSING_FIELDS",
                                          "name, value, and type are required");
          }

          std::optional<int64_t> oZoneId;
          if (jBody.contains("zone_id") && !jBody["zone_id"].is_null()) {
            oZoneId = jBody["zone_id"].get<int64_t>();
          }

          int64_t iId = _varRepo.create(sName, sValue, sType, sScope, oZoneId);
          return jsonResponse(201, {{"id", iId}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
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
          auto rcCtx = authenticate(_amMiddleware, req);
          requireRole(rcCtx, "viewer");

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
          requireRole(rcCtx, "operator");

          auto jBody = nlohmann::json::parse(req.body);
          std::string sValue = jBody.value("value", "");

          if (sValue.empty()) {
            throw common::ValidationError("MISSING_FIELDS", "value is required");
          }

          _varRepo.update(iId, sValue);
          return jsonResponse(200, {{"message", "Variable updated"}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
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
          auto rcCtx = authenticate(_amMiddleware, req);
          requireRole(rcCtx, "operator");

          _varRepo.deleteById(iId);
          return jsonResponse(200, {{"message", "Variable deleted"}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });
}

}  // namespace dns::api::routes
