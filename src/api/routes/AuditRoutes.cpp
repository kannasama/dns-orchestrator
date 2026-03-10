#include "api/routes/AuditRoutes.hpp"

#include <chrono>
#include <iomanip>
#include <sstream>

#include "api/AuthMiddleware.hpp"
#include "api/RouteHelpers.hpp"
#include "common/Errors.hpp"
#include "common/Permissions.hpp"
#include "dal/AuditRepository.hpp"

#include <nlohmann/json.hpp>

namespace dns::api::routes {
using namespace dns::common;

AuditRoutes::AuditRoutes(dns::dal::AuditRepository& arRepo,
                         const dns::api::AuthMiddleware& amMiddleware,
                         int iRetentionDays)
    : _arRepo(arRepo), _amMiddleware(amMiddleware), _iRetentionDays(iRetentionDays) {}

AuditRoutes::~AuditRoutes() = default;

namespace {

std::string formatTimestamp(std::chrono::system_clock::time_point tp) {
  auto tt = std::chrono::system_clock::to_time_t(tp);
  std::ostringstream oss;
  oss << std::put_time(std::gmtime(&tt), "%FT%TZ");
  return oss.str();
}

std::optional<std::chrono::system_clock::time_point> parseIso8601(const std::string& s) {
  std::tm tm = {};
  std::istringstream iss(s);
  iss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
  if (iss.fail()) return std::nullopt;
  return std::chrono::system_clock::from_time_t(timegm(&tm));
}

nlohmann::json auditRowToJson(const dns::dal::AuditLogRow& row) {
  nlohmann::json j = {
      {"id", row.iId},
      {"entity_type", row.sEntityType},
      {"operation", row.sOperation},
      {"identity", row.sIdentity},
      {"timestamp", formatTimestamp(row.tpTimestamp)},
  };
  if (row.oEntityId) j["entity_id"] = *row.oEntityId;
  if (row.ojOldValue) j["old_value"] = *row.ojOldValue;
  if (row.ojNewValue) j["new_value"] = *row.ojNewValue;
  if (row.osVariableUsed) j["variable_used"] = *row.osVariableUsed;
  if (row.osAuthMethod) j["auth_method"] = *row.osAuthMethod;
  if (row.osIpAddress) j["ip_address"] = *row.osIpAddress;
  return j;
}

}  // namespace

void AuditRoutes::registerRoutes(crow::SimpleApp& app) {
  // GET /api/v1/audit
  CROW_ROUTE(app, "/api/v1/audit").methods("GET"_method)(
      [this](const crow::request& req) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kAuditView);

          std::optional<std::string> osEntityType;
          std::optional<std::string> osIdentity;
          std::optional<std::chrono::system_clock::time_point> otpFrom;
          std::optional<std::chrono::system_clock::time_point> otpTo;
          int iLimit = 100;

          auto pEntityType = req.url_params.get("entity_type");
          if (pEntityType) osEntityType = std::string(pEntityType);

          auto pIdentity = req.url_params.get("identity");
          if (pIdentity) osIdentity = std::string(pIdentity);

          auto pFrom = req.url_params.get("from");
          if (pFrom) otpFrom = parseIso8601(pFrom);

          auto pTo = req.url_params.get("to");
          if (pTo) otpTo = parseIso8601(pTo);

          auto pLimit = req.url_params.get("limit");
          if (pLimit) iLimit = std::stoi(pLimit);

          auto vRows = _arRepo.query(osEntityType, std::nullopt, osIdentity,
                                     otpFrom, otpTo, iLimit);

          nlohmann::json jArr = nlohmann::json::array();
          for (const auto& row : vRows) {
            jArr.push_back(auditRowToJson(row));
          }
          return jsonResponse(200, jArr);
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });

  // GET /api/v1/audit/export
  CROW_ROUTE(app, "/api/v1/audit/export").methods("GET"_method)(
      [this](const crow::request& req) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kAuditExport);

          std::optional<std::chrono::system_clock::time_point> otpFrom;
          std::optional<std::chrono::system_clock::time_point> otpTo;

          auto pFrom = req.url_params.get("from");
          if (pFrom) otpFrom = parseIso8601(pFrom);

          auto pTo = req.url_params.get("to");
          if (pTo) otpTo = parseIso8601(pTo);

          // Fetch all matching entries (large limit for export)
          auto vRows = _arRepo.query(std::nullopt, std::nullopt, std::nullopt,
                                     otpFrom, otpTo, 100000);

          // Stream as NDJSON
          std::string sBody;
          for (const auto& row : vRows) {
            sBody += auditRowToJson(row).dump() + "\n";
          }

          crow::response resp(200, sBody);
          resp.set_header("Content-Type", "application/x-ndjson");
          return resp;
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });

  // DELETE /api/v1/audit/purge
  CROW_ROUTE(app, "/api/v1/audit/purge").methods("DELETE"_method)(
      [this](const crow::request& req) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kAuditPurge);

          auto prResult = _arRepo.purgeOld(_iRetentionDays);

          nlohmann::json jResult = {
              {"deleted", prResult.iDeletedCount},
          };
          if (prResult.oOldestRemaining) {
            jResult["oldest_remaining"] = formatTimestamp(*prResult.oOldestRemaining);
          }
          return jsonResponse(200, jResult);
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });
}

}  // namespace dns::api::routes
