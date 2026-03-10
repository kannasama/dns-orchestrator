#include "api/routes/SettingsRoutes.hpp"

#include "api/RouteHelpers.hpp"
#include "common/Permissions.hpp"
#include "common/SettingsDef.hpp"
#include "core/MaintenanceScheduler.hpp"
#include "dal/SettingsRepository.hpp"

#include <nlohmann/json.hpp>

#include <map>

namespace dns::api::routes {
using namespace dns::common;

SettingsRoutes::SettingsRoutes(dns::dal::SettingsRepository& srRepo,
                               const dns::api::AuthMiddleware& amMiddleware,
                               dns::core::MaintenanceScheduler* pScheduler)
    : _srRepo(srRepo), _amMiddleware(amMiddleware), _pScheduler(pScheduler) {}

SettingsRoutes::~SettingsRoutes() = default;

void SettingsRoutes::registerRoutes(crow::SimpleApp& app) {
  // GET /api/v1/settings — list all settings with metadata
  CROW_ROUTE(app, "/api/v1/settings")
      .methods(crow::HTTPMethod::GET)(
          [this](const crow::request& req) -> crow::response {
            try {
              auto rcCtx = authenticate(_amMiddleware, req);
              requirePermission(rcCtx, Permissions::kSettingsView);

              auto vRows = _srRepo.listAll();

              // Build a map from key → SettingDef for metadata lookup
              nlohmann::json jSettings = nlohmann::json::array();

              for (const auto& row : vRows) {
                // Skip internal keys (like setup_completed)
                bool bIsConfigSetting = false;
                std::string sCompiledDefault;
                bool bRestartRequired = false;

                for (const auto& def : dns::common::kSettings) {
                  if (def.sKey == row.sKey) {
                    bIsConfigSetting = true;
                    sCompiledDefault = std::string(def.sDefault);
                    bRestartRequired = def.bRestartRequired;
                    break;
                  }
                }

                if (!bIsConfigSetting) continue;

                nlohmann::json jRow = {
                    {"key", row.sKey},
                    {"value", row.sValue},
                    {"description", row.sDescription},
                    {"default", sCompiledDefault},
                    {"restart_required", bRestartRequired},
                    {"updated_at", row.sUpdatedAt},
                };
                jSettings.push_back(jRow);
              }

              return jsonResponse(200, jSettings);
            } catch (const common::AppError& e) {
              return errorResponse(e);
            }
          });

  // PUT /api/v1/settings — update one or more settings
  CROW_ROUTE(app, "/api/v1/settings")
      .methods(crow::HTTPMethod::PUT)(
          [this](const crow::request& req) -> crow::response {
            try {
              auto rcCtx = authenticate(_amMiddleware, req);
              requirePermission(rcCtx, Permissions::kSettingsEdit);

              auto jBody = nlohmann::json::parse(req.body);
              if (!jBody.is_object()) {
                throw common::ValidationError(
                    "invalid_body", "Request body must be a JSON object of key-value pairs");
              }

              nlohmann::json jUpdated = nlohmann::json::array();

              for (auto& [sKey, jValue] : jBody.items()) {
                // Validate key is a known setting
                bool bKnown = false;
                std::string sDescription;
                for (const auto& def : dns::common::kSettings) {
                  if (def.sKey == sKey) {
                    bKnown = true;
                    sDescription = std::string(def.sDescription);
                    break;
                  }
                }
                if (!bKnown) {
                  throw common::ValidationError(
                      "unknown_setting", "Unknown setting key: " + sKey);
                }

                std::string sNewValue;
                if (jValue.is_string()) {
                  sNewValue = jValue.get<std::string>();
                } else if (jValue.is_number_integer()) {
                  sNewValue = std::to_string(jValue.get<int64_t>());
                } else if (jValue.is_boolean()) {
                  sNewValue = jValue.get<bool>() ? "true" : "false";
                } else {
                  throw common::ValidationError(
                      "invalid_value",
                      "Setting value must be a string, integer, or boolean: " + sKey);
                }

                _srRepo.upsert(sKey, sNewValue, sDescription);
                jUpdated.push_back(sKey);
              }

              // Hot-reload maintenance intervals
              if (_pScheduler) {
                static const std::map<std::string, std::string> kIntervalMap = {
                    {"session.cleanup_interval_seconds", "session-flush"},
                    {"apikey.cleanup_interval_seconds", "api-key-cleanup"},
                    {"audit.purge_interval_seconds", "audit-purge"},
                    {"sync.check_interval_seconds", "sync-check"},
                };
                for (const auto& sKey : jUpdated) {
                  auto it = kIntervalMap.find(sKey.get<std::string>());
                  if (it != kIntervalMap.end()) {
                    int iNewInterval = _srRepo.getInt(it->first, 0);
                    if (iNewInterval > 0) {
                      _pScheduler->reschedule(it->second,
                                              std::chrono::seconds(iNewInterval));
                    }
                  }
                }
              }

              return jsonResponse(200, {{"message", "Settings updated"},
                                        {"updated", jUpdated}});
            } catch (const common::AppError& e) {
              return errorResponse(e);
            } catch (const nlohmann::json::exception&) {
              return invalidJsonResponse();
            }
          });
}

}  // namespace dns::api::routes
