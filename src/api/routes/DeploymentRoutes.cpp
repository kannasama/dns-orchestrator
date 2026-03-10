#include "api/routes/DeploymentRoutes.hpp"

#include <chrono>
#include <map>

#include "api/AuthMiddleware.hpp"
#include "api/RouteHelpers.hpp"
#include "common/Errors.hpp"
#include "common/Permissions.hpp"
#include "core/RollbackEngine.hpp"
#include "dal/DeploymentRepository.hpp"
#include "dal/RecordRepository.hpp"

#include <nlohmann/json.hpp>

namespace dns::api::routes {
using namespace dns::common;

DeploymentRoutes::DeploymentRoutes(dns::dal::DeploymentRepository& drRepo,
                                   dns::dal::RecordRepository& rrRepo,
                                   const dns::api::AuthMiddleware& amMiddleware,
                                   dns::core::RollbackEngine& reEngine)
    : _drRepo(drRepo), _rrRepo(rrRepo), _amMiddleware(amMiddleware), _reEngine(reEngine) {}

DeploymentRoutes::~DeploymentRoutes() = default;

namespace {

nlohmann::json deploymentRowToJson(const dns::dal::DeploymentRow& row) {
  return {
      {"id", row.iId},
      {"zone_id", row.iZoneId},
      {"deployed_by", row.iDeployedByUserId},
      {"deployed_at",
       std::chrono::duration_cast<std::chrono::seconds>(row.tpDeployedAt.time_since_epoch())
           .count()},
      {"seq", row.iSeq},
      {"snapshot", row.jSnapshot},
  };
}

}  // namespace

void DeploymentRoutes::registerRoutes(crow::SimpleApp& app) {
  // GET /api/v1/zones/<int>/deployments
  CROW_ROUTE(app, "/api/v1/zones/<int>/deployments").methods("GET"_method)(
      [this](const crow::request& req, int iZoneId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kZonesView);

          int iLimit = 50;
          auto sLimit = req.url_params.get("limit");
          if (sLimit) iLimit = std::stoi(sLimit);

          auto vRows = _drRepo.listByZoneId(iZoneId, iLimit);
          nlohmann::json jArr = nlohmann::json::array();
          for (const auto& row : vRows) {
            jArr.push_back(deploymentRowToJson(row));
          }
          return jsonResponse(200, jArr);
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });

  // GET /api/v1/zones/<int>/deployments/<int>
  CROW_ROUTE(app, "/api/v1/zones/<int>/deployments/<int>").methods("GET"_method)(
      [this](const crow::request& req, int /*iZoneId*/, int iDeployId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kZonesView);

          auto oRow = _drRepo.findById(iDeployId);
          if (!oRow) {
            throw common::NotFoundError("DEPLOYMENT_NOT_FOUND", "Deployment not found");
          }
          return jsonResponse(200, deploymentRowToJson(*oRow));
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });

  // GET /api/v1/zones/<int>/deployments/<int>/diff
  CROW_ROUTE(app, "/api/v1/zones/<int>/deployments/<int>/diff").methods("GET"_method)(
      [this](const crow::request& req, int iZoneId, int iDeployId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kZonesView);

          auto oDeploy = _drRepo.findById(iDeployId);
          if (!oDeploy) {
            throw common::NotFoundError("DEPLOYMENT_NOT_FOUND", "Deployment not found");
          }

          // Compare snapshot records vs current desired state
          auto vCurrentRecords = _rrRepo.listByZoneId(iZoneId);
          const auto& jSnapshotRecords = oDeploy->jSnapshot["records"];

          nlohmann::json jDiffs = nlohmann::json::array();

          // Build set of current records by name+type
          std::map<std::string, nlohmann::json> mCurrent;
          for (const auto& rec : vCurrentRecords) {
            std::string sKey = rec.sName + "|" + rec.sType;
            mCurrent[sKey] = {
                {"name", rec.sName}, {"type", rec.sType}, {"ttl", rec.iTtl},
                {"value_template", rec.sValueTemplate}, {"priority", rec.iPriority}};
          }

          // Build set of snapshot records by name+type
          std::map<std::string, nlohmann::json> mSnapshot;
          for (const auto& jRec : jSnapshotRecords) {
            std::string sKey = jRec.value("name", "") + "|" + jRec.value("type", "");
            mSnapshot[sKey] = jRec;
          }

          // Records in snapshot but not current -> "removed since deployment"
          for (const auto& [sKey, jRec] : mSnapshot) {
            if (mCurrent.find(sKey) == mCurrent.end()) {
              jDiffs.push_back({{"action", "removed"}, {"record", jRec}});
            }
          }

          // Records in current but not snapshot -> "added since deployment"
          for (const auto& [sKey, jRec] : mCurrent) {
            if (mSnapshot.find(sKey) == mSnapshot.end()) {
              jDiffs.push_back({{"action", "added"}, {"record", jRec}});
            }
          }

          // Records in both but different values -> "changed"
          for (const auto& [sKey, jCurRec] : mCurrent) {
            auto it = mSnapshot.find(sKey);
            if (it != mSnapshot.end()) {
              std::string sCurVal = jCurRec.value("value_template", "");
              std::string sSnapVal = it->second.value("value_template",
                                                      it->second.value("value", ""));
              if (sCurVal != sSnapVal) {
                jDiffs.push_back({
                    {"action", "changed"},
                    {"current", jCurRec},
                    {"snapshot", it->second},
                });
              }
            }
          }

          return jsonResponse(200, {{"deployment_id", iDeployId},
                                    {"zone_id", iZoneId},
                                    {"diffs", jDiffs}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });

  // POST /api/v1/zones/<int>/deployments/<int>/rollback
  CROW_ROUTE(app, "/api/v1/zones/<int>/deployments/<int>/rollback").methods("POST"_method)(
      [this](const crow::request& req, int iZoneId, int iDeployId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kZonesRollback);

          std::vector<int64_t> vCherryPickIds;
          if (!req.body.empty()) {
            try {
              auto jBody = nlohmann::json::parse(req.body);
              if (jBody.contains("cherry_pick_ids") && jBody["cherry_pick_ids"].is_array()) {
                for (const auto& jId : jBody["cherry_pick_ids"]) {
                  vCherryPickIds.push_back(jId.get<int64_t>());
                }
              }
            } catch (const nlohmann::json::exception&) {
              // Ignore parse errors — treat as full restore
            }
          }

          _reEngine.apply(iZoneId, iDeployId, vCherryPickIds,
                          rcCtx.iUserId, rcCtx.sUsername);

          return jsonResponse(200, {{"message", "Rollback applied — preview and push to deploy"}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });
}

}  // namespace dns::api::routes
