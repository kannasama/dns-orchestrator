#include "api/routes/RecordRoutes.hpp"

#include "api/AuthMiddleware.hpp"
#include "api/RequestValidator.hpp"
#include "api/RouteHelpers.hpp"
#include "common/Errors.hpp"
#include "common/Types.hpp"
#include "core/DeploymentEngine.hpp"
#include "core/DiffEngine.hpp"
#include "dal/RecordRepository.hpp"

#include <nlohmann/json.hpp>

namespace dns::api::routes {

RecordRoutes::RecordRoutes(dns::dal::RecordRepository& rrRepo,
                           const dns::api::AuthMiddleware& amMiddleware,
                           dns::core::DiffEngine& deEngine,
                           dns::core::DeploymentEngine& depEngine)
    : _rrRepo(rrRepo), _amMiddleware(amMiddleware),
      _deEngine(deEngine), _depEngine(depEngine) {}

RecordRoutes::~RecordRoutes() = default;

namespace {

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

          RequestValidator::validateRecordName(sName);
          RequestValidator::validateRecordType(sType);
          RequestValidator::validateTtl(iTtl);
          RequestValidator::validateValueTemplate(sValueTemplate);

          int64_t iId = _rrRepo.create(iZoneId, sName, sType, iTtl,
                                       sValueTemplate, iPriority);
          return jsonResponse(201, {{"id", iId}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        } catch (const nlohmann::json::exception&) {
          return invalidJsonResponse();
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

          RequestValidator::validateRecordName(sName);
          RequestValidator::validateRecordType(sType);
          RequestValidator::validateTtl(iTtl);
          RequestValidator::validateValueTemplate(sValueTemplate);

          _rrRepo.update(iRecordId, sName, sType, iTtl, sValueTemplate, iPriority);
          return jsonResponse(200, {{"message", "Record updated"}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        } catch (const nlohmann::json::exception&) {
          return invalidJsonResponse();
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

  // POST /api/v1/zones/<int>/preview
  CROW_ROUTE(app, "/api/v1/zones/<int>/preview").methods("POST"_method)(
      [this](const crow::request& req, int iZoneId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requireRole(rcCtx, "viewer");

          auto prResult = _deEngine.preview(iZoneId);

          nlohmann::json jDiffs = nlohmann::json::array();
          for (const auto& diff : prResult.vDiffs) {
            jDiffs.push_back({
                {"action", diff.action == common::DiffAction::Add      ? "add"
                           : diff.action == common::DiffAction::Update ? "update"
                           : diff.action == common::DiffAction::Delete ? "delete"
                                                                       : "drift"},
                {"name", diff.sName},
                {"type", diff.sType},
                {"source_value", diff.sSourceValue},
                {"provider_value", diff.sProviderValue},
                {"ttl", diff.uTtl},
                {"priority", diff.iPriority},
            });
          }

          nlohmann::json jResult = {
              {"zone_id", prResult.iZoneId},
              {"zone_name", prResult.sZoneName},
              {"has_drift", prResult.bHasDrift},
              {"diffs", jDiffs},
          };
          return jsonResponse(200, jResult);
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });

  // POST /api/v1/zones/<int>/push
  CROW_ROUTE(app, "/api/v1/zones/<int>/push").methods("POST"_method)(
      [this](const crow::request& req, int iZoneId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requireRole(rcCtx, "operator");

          bool bPurgeDrift = false;
          if (!req.body.empty()) {
            try {
              auto jBody = nlohmann::json::parse(req.body);
              bPurgeDrift = jBody.value("purge_drift", false);
            } catch (const nlohmann::json::exception&) {
              // Empty or invalid body — use defaults
            }
          }

          _depEngine.push(iZoneId, bPurgeDrift, rcCtx.iUserId, rcCtx.sUsername);
          return jsonResponse(200, {{"message", "Push completed successfully"}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });
}

}  // namespace dns::api::routes
