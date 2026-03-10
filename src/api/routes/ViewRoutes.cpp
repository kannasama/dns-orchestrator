#include "api/routes/ViewRoutes.hpp"

#include "api/AuthMiddleware.hpp"
#include "api/RouteHelpers.hpp"
#include "common/Errors.hpp"
#include "common/Permissions.hpp"
#include "dal/ViewRepository.hpp"

#include <nlohmann/json.hpp>

namespace dns::api::routes {
using namespace dns::common;

ViewRoutes::ViewRoutes(dns::dal::ViewRepository& vrRepo,
                       const dns::api::AuthMiddleware& amMiddleware)
    : _vrRepo(vrRepo), _amMiddleware(amMiddleware) {}

ViewRoutes::~ViewRoutes() = default;

void ViewRoutes::registerRoutes(crow::SimpleApp& app) {
  // GET /api/v1/views
  CROW_ROUTE(app, "/api/v1/views").methods("GET"_method)(
      [this](const crow::request& req) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kViewsView);

          auto vRows = _vrRepo.listAll();
          nlohmann::json jArr = nlohmann::json::array();
          for (const auto& row : vRows) {
            jArr.push_back({
                {"id", row.iId},
                {"name", row.sName},
                {"description", row.sDescription},
                {"provider_ids", row.vProviderIds},
                {"created_at", std::chrono::duration_cast<std::chrono::seconds>(
                                   row.tpCreatedAt.time_since_epoch())
                                   .count()},
            });
          }
          return jsonResponse(200, jArr);
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });

  // POST /api/v1/views
  CROW_ROUTE(app, "/api/v1/views").methods("POST"_method)(
      [this](const crow::request& req) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kViewsCreate);

          auto jBody = nlohmann::json::parse(req.body);
          std::string sName = jBody.value("name", "");
          std::string sDescription = jBody.value("description", "");

          if (sName.empty()) {
            throw common::ValidationError("MISSING_FIELDS", "name is required");
          }

          int64_t iId = _vrRepo.create(sName, sDescription);
          return jsonResponse(201, {{"id", iId}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        } catch (const nlohmann::json::exception&) {
          return invalidJsonResponse();
        }
      });

  // GET /api/v1/views/<int>
  CROW_ROUTE(app, "/api/v1/views/<int>").methods("GET"_method)(
      [this](const crow::request& req, int iId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kViewsView);

          auto oRow = _vrRepo.findWithProviders(iId);
          if (!oRow.has_value()) {
            throw common::NotFoundError("VIEW_NOT_FOUND", "View not found");
          }

          nlohmann::json jResp = {
              {"id", oRow->iId},
              {"name", oRow->sName},
              {"description", oRow->sDescription},
              {"provider_ids", oRow->vProviderIds},
              {"created_at", std::chrono::duration_cast<std::chrono::seconds>(
                                 oRow->tpCreatedAt.time_since_epoch())
                                 .count()},
          };
          return jsonResponse(200, jResp);
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });

  // PUT /api/v1/views/<int>
  CROW_ROUTE(app, "/api/v1/views/<int>").methods("PUT"_method)(
      [this](const crow::request& req, int iId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kViewsEdit);

          auto jBody = nlohmann::json::parse(req.body);
          std::string sName = jBody.value("name", "");
          std::string sDescription = jBody.value("description", "");

          if (sName.empty()) {
            throw common::ValidationError("MISSING_FIELDS", "name is required");
          }

          _vrRepo.update(iId, sName, sDescription);
          return jsonResponse(200, {{"message", "View updated"}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        } catch (const nlohmann::json::exception&) {
          return invalidJsonResponse();
        }
      });

  // DELETE /api/v1/views/<int>
  CROW_ROUTE(app, "/api/v1/views/<int>").methods("DELETE"_method)(
      [this](const crow::request& req, int iId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kViewsDelete);

          _vrRepo.deleteById(iId);
          return jsonResponse(200, {{"message", "View deleted"}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });

  // POST /api/v1/views/<int>/providers/<int>
  CROW_ROUTE(app, "/api/v1/views/<int>/providers/<int>").methods("POST"_method)(
      [this](const crow::request& req, int iViewId, int iProviderId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kViewsEdit);

          _vrRepo.attachProvider(iViewId, iProviderId);
          return jsonResponse(200, {{"message", "Provider attached"}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });

  // DELETE /api/v1/views/<int>/providers/<int>
  CROW_ROUTE(app, "/api/v1/views/<int>/providers/<int>").methods("DELETE"_method)(
      [this](const crow::request& req, int iViewId, int iProviderId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kViewsEdit);

          _vrRepo.detachProvider(iViewId, iProviderId);
          return jsonResponse(200, {{"message", "Provider detached"}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });
}

}  // namespace dns::api::routes
