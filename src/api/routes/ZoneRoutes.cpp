#include "api/routes/ZoneRoutes.hpp"

#include "api/AuthMiddleware.hpp"
#include "api/RequestValidator.hpp"
#include "api/RouteHelpers.hpp"
#include "common/Errors.hpp"
#include "common/Permissions.hpp"
#include "core/DiffEngine.hpp"
#include "dal/ZoneRepository.hpp"

#include <nlohmann/json.hpp>

namespace dns::api::routes {
using namespace dns::common;

ZoneRoutes::ZoneRoutes(dns::dal::ZoneRepository& zrRepo,
                       const dns::api::AuthMiddleware& amMiddleware,
                       dns::core::DiffEngine& deEngine)
    : _zrRepo(zrRepo), _amMiddleware(amMiddleware), _deEngine(deEngine) {}

ZoneRoutes::~ZoneRoutes() = default;

namespace {

nlohmann::json zoneRowToJson(const dns::dal::ZoneRow& row) {
  nlohmann::json j = {
      {"id", row.iId},
      {"name", row.sName},
      {"view_id", row.iViewId},
      {"manage_soa", row.bManageSoa},
      {"manage_ns", row.bManageNs},
      {"created_at", std::chrono::duration_cast<std::chrono::seconds>(
                         row.tpCreatedAt.time_since_epoch())
                         .count()},
  };
  if (row.oDeploymentRetention.has_value()) {
    j["deployment_retention"] = *row.oDeploymentRetention;
  } else {
    j["deployment_retention"] = nullptr;
  }
  j["sync_status"] = row.sSyncStatus;
  if (row.oSyncCheckedAt.has_value()) {
    j["sync_checked_at"] = std::chrono::duration_cast<std::chrono::seconds>(
                               row.oSyncCheckedAt->time_since_epoch())
                               .count();
  } else {
    j["sync_checked_at"] = nullptr;
  }
  j["git_repo_id"] = row.oGitRepoId.has_value() ? nlohmann::json(*row.oGitRepoId)
                                                  : nlohmann::json(nullptr);
  j["git_branch"] = row.oGitBranch.has_value() ? nlohmann::json(*row.oGitBranch)
                                                : nlohmann::json(nullptr);
  return j;
}

}  // namespace

void ZoneRoutes::registerRoutes(crow::SimpleApp& app) {
  // POST /api/v1/zones/sync-check (bulk) — registered FIRST to avoid Crow matching as <int>
  CROW_ROUTE(app, "/api/v1/zones/sync-check").methods("POST"_method)(
      [this](const crow::request& req) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kZonesCreate);
          auto vZones = _zrRepo.listAll();
          nlohmann::json jResults = nlohmann::json::array();
          for (const auto& zone : vZones) {
            std::string sStatus = "in_sync";
            try {
              auto preview = _deEngine.preview(zone.iId);
              sStatus = preview.bHasDrift ? "drift" : "in_sync";
            } catch (...) {
              sStatus = "error";
            }
            _zrRepo.updateSyncStatus(zone.iId, sStatus);
            auto oUpdated = _zrRepo.findById(zone.iId);
            nlohmann::json jEntry = {{"zone_id", zone.iId}, {"sync_status", sStatus}};
            if (oUpdated && oUpdated->oSyncCheckedAt.has_value()) {
              jEntry["sync_checked_at"] = std::chrono::duration_cast<std::chrono::seconds>(
                  oUpdated->oSyncCheckedAt->time_since_epoch()).count();
            } else {
              jEntry["sync_checked_at"] = nullptr;
            }
            jResults.push_back(jEntry);
          }
          auto iServerNow = std::chrono::duration_cast<std::chrono::seconds>(
              std::chrono::system_clock::now().time_since_epoch()).count();
          return jsonResponse(200, {{"results", jResults}, {"server_time", iServerNow}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });

  // POST /api/v1/zones/<int>/sync-check (single zone)
  CROW_ROUTE(app, "/api/v1/zones/<int>/sync-check").methods("POST"_method)(
      [this](const crow::request& req, int iZoneId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kRecordsImport);
          auto oZone = _zrRepo.findById(iZoneId);
          if (!oZone) throw common::NotFoundError("ZONE_NOT_FOUND", "Zone not found");
          std::string sStatus = "in_sync";
          try {
            auto preview = _deEngine.preview(iZoneId);
            sStatus = preview.bHasDrift ? "drift" : "in_sync";
          } catch (...) {
            sStatus = "error";
          }
          _zrRepo.updateSyncStatus(iZoneId, sStatus);
          auto oUpdated = _zrRepo.findById(iZoneId);
          nlohmann::json jResult = {
              {"zone_id", iZoneId},
              {"sync_status", oUpdated->sSyncStatus},
          };
          if (oUpdated->oSyncCheckedAt.has_value()) {
            jResult["sync_checked_at"] = std::chrono::duration_cast<std::chrono::seconds>(
                oUpdated->oSyncCheckedAt->time_since_epoch()).count();
          } else {
            jResult["sync_checked_at"] = nullptr;
          }
          jResult["server_time"] = std::chrono::duration_cast<std::chrono::seconds>(
              std::chrono::system_clock::now().time_since_epoch()).count();
          return jsonResponse(200, jResult);
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });

  // GET /api/v1/zones
  CROW_ROUTE(app, "/api/v1/zones").methods("GET"_method)(
      [this](const crow::request& req) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kZonesView);

          // Check for ?view_id= query parameter
          auto sViewId = req.url_params.get("view_id");
          std::vector<dns::dal::ZoneRow> vRows;
          if (sViewId) {
            vRows = _zrRepo.listByViewId(std::stoll(sViewId));
          } else {
            vRows = _zrRepo.listAll();
          }

          nlohmann::json jArr = nlohmann::json::array();
          for (const auto& row : vRows) {
            jArr.push_back(zoneRowToJson(row));
          }
          return jsonResponse(200, jArr);
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });

  // POST /api/v1/zones
  CROW_ROUTE(app, "/api/v1/zones").methods("POST"_method)(
      [this](const crow::request& req) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kZonesEdit);

          auto jBody = nlohmann::json::parse(req.body);
          std::string sName = jBody.value("name", "");
          int64_t iViewId = jBody.value("view_id", int64_t{0});

          RequestValidator::validateZoneName(sName);
          if (iViewId == 0) {
            throw common::ValidationError("MISSING_FIELDS", "view_id is required");
          }

          std::optional<int> oRetention;
          if (jBody.contains("deployment_retention") &&
              !jBody["deployment_retention"].is_null()) {
            oRetention = jBody["deployment_retention"].get<int>();
          }

          bool bManageSoa = jBody.value("manage_soa", false);
          bool bManageNs = jBody.value("manage_ns", false);

          std::optional<int64_t> oGitRepoId;
          if (jBody.contains("git_repo_id") && !jBody["git_repo_id"].is_null()) {
            oGitRepoId = jBody["git_repo_id"].get<int64_t>();
          }
          std::optional<std::string> oGitBranch;
          if (jBody.contains("git_branch") && !jBody["git_branch"].is_null()) {
            oGitBranch = jBody["git_branch"].get<std::string>();
            RequestValidator::validateGitBranch(*oGitBranch);
          }

          int64_t iId = _zrRepo.create(sName, iViewId, oRetention, bManageSoa, bManageNs,
                                       oGitRepoId, oGitBranch);
          return jsonResponse(201, {{"id", iId}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        } catch (const nlohmann::json::exception&) {
          return invalidJsonResponse();
        }
      });

  // GET /api/v1/zones/<int>
  CROW_ROUTE(app, "/api/v1/zones/<int>").methods("GET"_method)(
      [this](const crow::request& req, int iId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kZonesView);

          auto oRow = _zrRepo.findById(iId);
          if (!oRow.has_value()) {
            throw common::NotFoundError("ZONE_NOT_FOUND", "Zone not found");
          }
          return jsonResponse(200, zoneRowToJson(*oRow));
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });

  // PUT /api/v1/zones/<int>
  CROW_ROUTE(app, "/api/v1/zones/<int>").methods("PUT"_method)(
      [this](const crow::request& req, int iId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kZonesEdit);

          auto jBody = nlohmann::json::parse(req.body);
          std::string sName = jBody.value("name", "");

          RequestValidator::validateZoneName(sName);

          int64_t iViewId = jBody.value("view_id", static_cast<int64_t>(0));
          if (iViewId <= 0) {
            throw common::ValidationError("INVALID_VIEW", "view_id is required");
          }

          std::optional<int> oRetention;
          if (jBody.contains("deployment_retention") &&
              !jBody["deployment_retention"].is_null()) {
            oRetention = jBody["deployment_retention"].get<int>();
          }

          bool bManageSoa = jBody.value("manage_soa", false);
          bool bManageNs = jBody.value("manage_ns", false);

          std::optional<int64_t> oGitRepoId;
          if (jBody.contains("git_repo_id") && !jBody["git_repo_id"].is_null()) {
            oGitRepoId = jBody["git_repo_id"].get<int64_t>();
          }
          std::optional<std::string> oGitBranch;
          if (jBody.contains("git_branch") && !jBody["git_branch"].is_null()) {
            oGitBranch = jBody["git_branch"].get<std::string>();
            RequestValidator::validateGitBranch(*oGitBranch);
          }

          _zrRepo.update(iId, sName, iViewId, oRetention, bManageSoa, bManageNs,
                         oGitRepoId, oGitBranch);
          return jsonResponse(200, {{"message", "Zone updated"}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        } catch (const nlohmann::json::exception&) {
          return invalidJsonResponse();
        }
      });

  // DELETE /api/v1/zones/<int>
  CROW_ROUTE(app, "/api/v1/zones/<int>").methods("DELETE"_method)(
      [this](const crow::request& req, int iId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kZonesDelete);

          _zrRepo.deleteById(iId);
          return jsonResponse(200, {{"message", "Zone deleted"}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });
}

}  // namespace dns::api::routes
