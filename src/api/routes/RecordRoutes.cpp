#include "api/routes/RecordRoutes.hpp"

#include "api/AuthMiddleware.hpp"
#include "common/Errors.hpp"
#include "dal/RecordRepository.hpp"

#include <nlohmann/json.hpp>

namespace dns::api::routes {

RecordRoutes::RecordRoutes(dns::dal::RecordRepository& rrRepo,
                           const dns::api::AuthMiddleware& amMiddleware)
    : _rrRepo(rrRepo), _amMiddleware(amMiddleware) {}

RecordRoutes::~RecordRoutes() = default;

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

nlohmann::json recordRowToJson(const dns::dal::RecordRow& row) {
  nlohmann::json j = {
      {"id", row.iId},
      {"zone_id", row.iZoneId},
      {"name", row.sName},
      {"type", row.sType},
      {"ttl", row.iTtl},
      {"value_template", row.sValueTemplate},
      {"priority", row.iPriority},
      {"created_at", std::chrono::duration_cast<std::chrono::seconds>(
                         row.tpCreatedAt.time_since_epoch())
                         .count()},
      {"updated_at", std::chrono::duration_cast<std::chrono::seconds>(
                         row.tpUpdatedAt.time_since_epoch())
                         .count()},
  };
  if (row.oLastAuditId.has_value()) {
    j["last_audit_id"] = *row.oLastAuditId;
  } else {
    j["last_audit_id"] = nullptr;
  }
  return j;
}

}  // namespace

void RecordRoutes::registerRoutes(crow::SimpleApp& app) {
  // GET /api/v1/zones/<int>/records
  CROW_ROUTE(app, "/api/v1/zones/<int>/records").methods("GET"_method)(
      [this](const crow::request& req, int iZoneId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requireRole(rcCtx, "viewer");

          auto vRows = _rrRepo.listByZoneId(iZoneId);
          nlohmann::json jArr = nlohmann::json::array();
          for (const auto& row : vRows) {
            jArr.push_back(recordRowToJson(row));
          }
          return jsonResponse(200, jArr);
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });

  // POST /api/v1/zones/<int>/records
  CROW_ROUTE(app, "/api/v1/zones/<int>/records").methods("POST"_method)(
      [this](const crow::request& req, int iZoneId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requireRole(rcCtx, "operator");

          auto jBody = nlohmann::json::parse(req.body);
          std::string sName = jBody.value("name", "");
          std::string sType = jBody.value("type", "");
          int iTtl = jBody.value("ttl", 300);
          std::string sValueTemplate = jBody.value("value_template", "");
          int iPriority = jBody.value("priority", 0);

          if (sName.empty() || sType.empty() || sValueTemplate.empty()) {
            throw common::ValidationError("MISSING_FIELDS",
                                          "name, type, and value_template are required");
          }

          int64_t iId = _rrRepo.create(iZoneId, sName, sType, iTtl,
                                       sValueTemplate, iPriority);
          return jsonResponse(201, {{"id", iId}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        } catch (const nlohmann::json::exception&) {
          nlohmann::json jErr = {{"error", "invalid_json"},
                                 {"message", "Invalid JSON body"}};
          return crow::response(400, jErr.dump(2));
        }
      });

  // GET /api/v1/zones/<int>/records/<int>
  CROW_ROUTE(app, "/api/v1/zones/<int>/records/<int>").methods("GET"_method)(
      [this](const crow::request& req, int /*iZoneId*/, int iRecordId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requireRole(rcCtx, "viewer");

          auto oRow = _rrRepo.findById(iRecordId);
          if (!oRow.has_value()) {
            throw common::NotFoundError("RECORD_NOT_FOUND", "Record not found");
          }
          return jsonResponse(200, recordRowToJson(*oRow));
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });

  // PUT /api/v1/zones/<int>/records/<int>
  CROW_ROUTE(app, "/api/v1/zones/<int>/records/<int>").methods("PUT"_method)(
      [this](const crow::request& req, int /*iZoneId*/, int iRecordId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requireRole(rcCtx, "operator");

          auto jBody = nlohmann::json::parse(req.body);
          std::string sName = jBody.value("name", "");
          std::string sType = jBody.value("type", "");
          int iTtl = jBody.value("ttl", 300);
          std::string sValueTemplate = jBody.value("value_template", "");
          int iPriority = jBody.value("priority", 0);

          if (sName.empty() || sType.empty() || sValueTemplate.empty()) {
            throw common::ValidationError("MISSING_FIELDS",
                                          "name, type, and value_template are required");
          }

          _rrRepo.update(iRecordId, sName, sType, iTtl, sValueTemplate, iPriority);
          return jsonResponse(200, {{"message", "Record updated"}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        } catch (const nlohmann::json::exception&) {
          nlohmann::json jErr = {{"error", "invalid_json"},
                                 {"message", "Invalid JSON body"}};
          return crow::response(400, jErr.dump(2));
        }
      });

  // DELETE /api/v1/zones/<int>/records/<int>
  CROW_ROUTE(app, "/api/v1/zones/<int>/records/<int>").methods("DELETE"_method)(
      [this](const crow::request& req, int /*iZoneId*/, int iRecordId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requireRole(rcCtx, "operator");

          _rrRepo.deleteById(iRecordId);
          return jsonResponse(200, {{"message", "Record deleted"}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });
}

}  // namespace dns::api::routes
