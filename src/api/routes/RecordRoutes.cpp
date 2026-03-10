#include "api/routes/RecordRoutes.hpp"

#include "api/AuthMiddleware.hpp"
#include "api/RequestValidator.hpp"
#include "api/RouteHelpers.hpp"
#include "common/Errors.hpp"
#include "common/Permissions.hpp"
#include "common/Types.hpp"
#include "core/DeploymentEngine.hpp"
#include "core/DiffEngine.hpp"
#include "dal/AuditRepository.hpp"
#include "dal/RecordRepository.hpp"
#include "dal/ZoneRepository.hpp"

#include <nlohmann/json.hpp>

namespace dns::api::routes {
using namespace dns::common;

RecordRoutes::RecordRoutes(dns::dal::RecordRepository& rrRepo,
                           dns::dal::ZoneRepository& zrRepo,
                           dns::dal::AuditRepository& arRepo,
                           const dns::api::AuthMiddleware& amMiddleware,
                           dns::core::DiffEngine& deEngine,
                           dns::core::DeploymentEngine& depEngine)
    : _rrRepo(rrRepo), _zrRepo(zrRepo), _arRepo(arRepo), _amMiddleware(amMiddleware),
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
  if (!row.jProviderMeta.is_null()) {
    j["provider_meta"] = row.jProviderMeta;
  } else {
    j["provider_meta"] = nullptr;
  }
  j["pending_delete"] = row.bPendingDelete;
  return j;
}

}  // namespace

void RecordRoutes::registerRoutes(crow::SimpleApp& app) {
  // GET /api/v1/zones/<int>/records
  CROW_ROUTE(app, "/api/v1/zones/<int>/records").methods("GET"_method)(
      [this](const crow::request& req, int iZoneId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kRecordsView);

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
          requirePermission(rcCtx, Permissions::kRecordsCreate);

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

          nlohmann::json jProviderMeta;
          if (jBody.contains("provider_meta") && jBody["provider_meta"].is_object()) {
            jProviderMeta = jBody["provider_meta"];
          }

          int64_t iId = _rrRepo.create(iZoneId, sName, sType, iTtl,
                                       sValueTemplate, iPriority, jProviderMeta);

          // Audit trail
          nlohmann::json jNewValue = {
              {"name", sName}, {"type", sType}, {"ttl", iTtl},
              {"value_template", sValueTemplate}, {"priority", iPriority},
          };
          _arRepo.insert("record", iId, "create", std::nullopt, jNewValue,
                         rcCtx.sUsername, std::nullopt, std::nullopt);

          auto oCreated = _rrRepo.findById(iId);
          return jsonResponse(201, recordRowToJson(*oCreated));
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
          requirePermission(rcCtx, Permissions::kRecordsView);

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
          requirePermission(rcCtx, Permissions::kRecordsEdit);

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

          nlohmann::json jProviderMeta;
          if (jBody.contains("provider_meta") && jBody["provider_meta"].is_object()) {
            jProviderMeta = jBody["provider_meta"];
          }

          // Capture old state for audit
          auto oOldRecord = _rrRepo.findById(iRecordId);
          nlohmann::json jOldValue;
          if (oOldRecord) {
            jOldValue = {
                {"name", oOldRecord->sName}, {"type", oOldRecord->sType},
                {"ttl", oOldRecord->iTtl},
                {"value_template", oOldRecord->sValueTemplate},
                {"priority", oOldRecord->iPriority},
            };
          }

          _rrRepo.update(iRecordId, sName, sType, iTtl, sValueTemplate, iPriority, jProviderMeta);

          // Audit trail
          nlohmann::json jNewValue = {
              {"name", sName}, {"type", sType}, {"ttl", iTtl},
              {"value_template", sValueTemplate}, {"priority", iPriority},
          };
          _arRepo.insert("record", iRecordId, "update", jOldValue, jNewValue,
                         rcCtx.sUsername, std::nullopt, std::nullopt);

          auto oUpdated = _rrRepo.findById(iRecordId);
          return jsonResponse(200, recordRowToJson(*oUpdated));
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
          requirePermission(rcCtx, Permissions::kRecordsDelete);

          // Capture old state for audit
          auto oOldRecord = _rrRepo.findById(iRecordId);
          nlohmann::json jOldValue;
          if (oOldRecord) {
            jOldValue = {
                {"name", oOldRecord->sName}, {"type", oOldRecord->sType},
                {"ttl", oOldRecord->iTtl},
                {"value_template", oOldRecord->sValueTemplate},
                {"priority", oOldRecord->iPriority},
            };
          }

          _rrRepo.deleteById(iRecordId);

          // Audit trail
          _arRepo.insert("record", iRecordId, "delete", jOldValue, std::nullopt,
                         rcCtx.sUsername, std::nullopt, std::nullopt);

          return jsonResponse(200, {{"message", "Record marked for deletion"}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });

  // POST /api/v1/zones/<int>/records/<int>/restore
  CROW_ROUTE(app, "/api/v1/zones/<int>/records/<int>/restore").methods("POST"_method)(
      [this](const crow::request& req, int /*iZoneId*/, int iRecordId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kZonesDeploy);

          _rrRepo.restoreById(iRecordId);

          // Audit trail
          auto oRestored = _rrRepo.findById(iRecordId);
          nlohmann::json jNewValue;
          if (oRestored) {
            jNewValue = {
                {"name", oRestored->sName}, {"type", oRestored->sType},
                {"ttl", oRestored->iTtl},
                {"value_template", oRestored->sValueTemplate},
                {"priority", oRestored->iPriority},
            };
          }
          _arRepo.insert("record", iRecordId, "restore", std::nullopt, jNewValue,
                         rcCtx.sUsername, std::nullopt, std::nullopt);

          return jsonResponse(200, recordRowToJson(*oRestored));
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });

  // POST /api/v1/zones/<int>/preview
  CROW_ROUTE(app, "/api/v1/zones/<int>/preview").methods("POST"_method)(
      [this](const crow::request& req, int iZoneId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kZonesView);

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

          // Per-provider breakdown
          nlohmann::json jProviders = nlohmann::json::array();
          for (const auto& ppr : prResult.vProviderPreviews) {
            nlohmann::json jProviderDiffs = nlohmann::json::array();
            for (const auto& d : ppr.vDiffs) {
              jProviderDiffs.push_back({
                  {"action", d.action == common::DiffAction::Add      ? "add"
                             : d.action == common::DiffAction::Update ? "update"
                             : d.action == common::DiffAction::Delete ? "delete"
                                                                      : "drift"},
                  {"name", d.sName},
                  {"type", d.sType},
                  {"source_value", d.sSourceValue},
                  {"provider_value", d.sProviderValue},
                  {"ttl", d.uTtl},
                  {"priority", d.iPriority},
              });
            }
            jProviders.push_back({
                {"provider_id", ppr.iProviderId},
                {"provider_name", ppr.sProviderName},
                {"provider_type", ppr.sProviderType},
                {"has_drift", ppr.bHasDrift},
                {"diffs", jProviderDiffs},
            });
          }

          nlohmann::json jResult = {
              {"zone_id", prResult.iZoneId},
              {"zone_name", prResult.sZoneName},
              {"has_drift", prResult.bHasDrift},
              {"diffs", jDiffs},
              {"providers", jProviders},
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
          requirePermission(rcCtx, Permissions::kZonesDeploy);

          std::vector<common::DriftAction> vDriftActions;
          if (!req.body.empty()) {
            try {
              auto jBody = nlohmann::json::parse(req.body);
              if (jBody.contains("drift_actions") && jBody["drift_actions"].is_array()) {
                for (const auto& jAction : jBody["drift_actions"]) {
                  common::DriftAction da;
                  da.sName = jAction.value("name", "");
                  da.sType = jAction.value("type", "");
                  da.sAction = jAction.value("action", "");
                  if (da.sAction != "adopt" && da.sAction != "delete" && da.sAction != "ignore") {
                    throw common::ValidationError(
                        "INVALID_DRIFT_ACTION",
                        "drift action must be 'adopt', 'delete', or 'ignore'");
                  }
                  vDriftActions.push_back(std::move(da));
                }
              }
            } catch (const nlohmann::json::exception&) {
              // Empty or invalid body
            }
          }

          _depEngine.push(iZoneId, vDriftActions, rcCtx.iUserId, rcCtx.sUsername);
          return jsonResponse(200, {{"message", "Push completed successfully"}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });

  // POST /api/v1/zones/<int>/records/batch
  CROW_ROUTE(app, "/api/v1/zones/<int>/records/batch").methods("POST"_method)(
      [this](const crow::request& req, int iZoneId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kRecordsImport);

          auto jBody = nlohmann::json::parse(req.body);
          if (!jBody.is_array()) {
            throw common::ValidationError("INVALID_BODY", "Request body must be a JSON array");
          }
          if (jBody.empty()) {
            throw common::ValidationError("EMPTY_BATCH", "Batch cannot be empty");
          }
          if (jBody.size() > 500) {
            throw common::ValidationError("BATCH_TOO_LARGE", "Maximum 500 records per batch");
          }

          std::vector<std::tuple<std::string, std::string, int, std::string, int>> vRecords;
          vRecords.reserve(jBody.size());

          for (size_t i = 0; i < jBody.size(); ++i) {
            const auto& jRec = jBody[i];
            std::string sName = jRec.value("name", "");
            std::string sType = jRec.value("type", "");
            int iTtl = jRec.value("ttl", 300);
            std::string sValueTemplate = jRec.value("value_template", "");
            int iPriority = jRec.value("priority", 0);

            try {
              RequestValidator::validateRecordName(sName);
              RequestValidator::validateRecordType(sType);
              RequestValidator::validateTtl(iTtl);
              RequestValidator::validateValueTemplate(sValueTemplate);
            } catch (const common::ValidationError& e) {
              throw common::ValidationError(
                  "RECORD_VALIDATION_FAILED",
                  "Record " + std::to_string(i) + ": " + e.what());
            }

            vRecords.emplace_back(sName, sType, iTtl, sValueTemplate, iPriority);
          }

          auto vIds = _rrRepo.createBatch(iZoneId, vRecords);

          nlohmann::json jIds = nlohmann::json::array();
          for (auto id : vIds) jIds.push_back(id);
          return jsonResponse(201, {{"ids", jIds}, {"count", vIds.size()}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        } catch (const nlohmann::json::exception&) {
          return invalidJsonResponse();
        }
      });

  // PUT /api/v1/zones/<int>/records/batch
  CROW_ROUTE(app, "/api/v1/zones/<int>/records/batch").methods("PUT"_method)(
      [this](const crow::request& req, int iZoneId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kRecordsView);

          auto jBody = nlohmann::json::parse(req.body);

          // Process updates
          std::vector<dns::dal::RecordRepository::BatchUpdateEntry> vUpdates;
          nlohmann::json jAuditUpdates = nlohmann::json::array();

          if (jBody.contains("updates") && jBody["updates"].is_array()) {
            for (const auto& jUpd : jBody["updates"]) {
              dns::dal::RecordRepository::BatchUpdateEntry entry;
              entry.iId = jUpd.value("id", int64_t{0});
              if (entry.iId == 0) {
                throw common::ValidationError("MISSING_ID", "Each update must have an 'id'");
              }
              if (jUpd.contains("name")) entry.oName = jUpd["name"].get<std::string>();
              if (jUpd.contains("type")) entry.oType = jUpd["type"].get<std::string>();
              if (jUpd.contains("ttl")) entry.oTtl = jUpd["ttl"].get<int>();
              if (jUpd.contains("value_template"))
                entry.oValueTemplate = jUpd["value_template"].get<std::string>();
              if (jUpd.contains("priority")) entry.oPriority = jUpd["priority"].get<int>();
              if (jUpd.contains("provider_meta"))
                entry.oProviderMeta = jUpd["provider_meta"];

              // Capture old state for audit trail
              auto oOldRec = _rrRepo.findById(entry.iId);
              nlohmann::json jAuditEntry = jUpd;
              if (oOldRec) {
                jAuditEntry["record_name"] = oOldRec->sName;
                jAuditEntry["record_type"] = oOldRec->sType;
                nlohmann::json jOld;
                if (entry.oName) jOld["name"] = oOldRec->sName;
                if (entry.oType) jOld["type"] = oOldRec->sType;
                if (entry.oTtl) jOld["ttl"] = oOldRec->iTtl;
                if (entry.oValueTemplate) jOld["value_template"] = oOldRec->sValueTemplate;
                if (entry.oPriority) jOld["priority"] = oOldRec->iPriority;
                if (entry.oProviderMeta) jOld["provider_meta"] = oOldRec->jProviderMeta;
                jAuditEntry["old"] = jOld;
              }
              jAuditUpdates.push_back(jAuditEntry);

              vUpdates.push_back(std::move(entry));
            }
          }

          // Process deletes
          std::vector<int64_t> vDeleteIds;
          nlohmann::json jAuditDeletes = nlohmann::json::array();

          if (jBody.contains("deletes") && jBody["deletes"].is_array()) {
            for (const auto& jId : jBody["deletes"]) {
              int64_t iId = jId.get<int64_t>();
              vDeleteIds.push_back(iId);
              // Capture full record info for audit trail
              auto oRec = _rrRepo.findById(iId);
              if (oRec) {
                jAuditDeletes.push_back({
                    {"id", iId},
                    {"name", oRec->sName},
                    {"type", oRec->sType},
                    {"ttl", oRec->iTtl},
                    {"value_template", oRec->sValueTemplate},
                });
              } else {
                jAuditDeletes.push_back(iId);
              }
            }
          }

          if (vUpdates.empty() && vDeleteIds.empty()) {
            throw common::ValidationError("EMPTY_BATCH", "No updates or deletes specified");
          }

          if (!vUpdates.empty()) {
            _rrRepo.batchUpdate(iZoneId, vUpdates);
          }
          if (!vDeleteIds.empty()) {
            _rrRepo.batchSoftDelete(iZoneId, vDeleteIds);
          }

          // Single audit entry for the entire batch
          nlohmann::json jNewValue = {
              {"updates", jAuditUpdates},
              {"deletes", jAuditDeletes},
          };
          _arRepo.insert("record", iZoneId, "batch_update", std::nullopt, jNewValue,
                         rcCtx.sUsername, std::nullopt, std::nullopt);

          // Return updated records list
          auto vRows = _rrRepo.listByZoneId(iZoneId);
          nlohmann::json jArr = nlohmann::json::array();
          for (const auto& row : vRows) {
            jArr.push_back(recordRowToJson(row));
          }
          return jsonResponse(200, jArr);
        } catch (const common::AppError& e) {
          return errorResponse(e);
        } catch (const nlohmann::json::exception&) {
          return invalidJsonResponse();
        }
      });

  // GET /api/v1/zones/<int>/provider-records
  CROW_ROUTE(app, "/api/v1/zones/<int>/provider-records").methods("GET"_method)(
      [this](const crow::request& req, int iZoneId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kVariablesView);

          auto vLiveRecords = _deEngine.fetchLiveRecords(iZoneId);

          auto oZone = _zrRepo.findById(iZoneId);
          if (!oZone) {
            throw common::NotFoundError("ZONE_NOT_FOUND", "Zone not found");
          }

          std::erase_if(vLiveRecords, [&](const auto& dr) {
            if (!oZone->bManageSoa && dr.sType == "SOA") return true;
            if (!oZone->bManageNs && dr.sType == "NS") return true;
            return false;
          });

          nlohmann::json jRecords = nlohmann::json::array();
          for (const auto& dr : vLiveRecords) {
            jRecords.push_back({
                {"name", dr.sName},
                {"type", dr.sType},
                {"value", dr.sValue},
                {"ttl", dr.uTtl},
                {"priority", dr.iPriority},
            });
          }
          return jsonResponse(200, jRecords);
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });
}

}  // namespace dns::api::routes
