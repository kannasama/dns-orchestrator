#include "api/routes/GroupRoutes.hpp"

#include "api/AuthMiddleware.hpp"
#include "api/RequestValidator.hpp"
#include "api/RouteHelpers.hpp"
#include "common/Errors.hpp"
#include "common/Permissions.hpp"
#include "dal/GroupRepository.hpp"

#include <nlohmann/json.hpp>

namespace dns::api::routes {
using namespace dns::common;

GroupRoutes::GroupRoutes(dns::dal::GroupRepository& grRepo,
                        const dns::api::AuthMiddleware& amMiddleware)
    : _grRepo(grRepo), _amMiddleware(amMiddleware) {}

GroupRoutes::~GroupRoutes() = default;

void GroupRoutes::registerRoutes(crow::SimpleApp& app) {
  // GET /api/v1/groups
  CROW_ROUTE(app, "/api/v1/groups").methods("GET"_method)(
      [this](const crow::request& req) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kGroupsView);

          auto vGroups = _grRepo.listAll();
          nlohmann::json jArr = nlohmann::json::array();
          for (const auto& group : vGroups) {
            jArr.push_back({
                {"id", group.iId},
                {"name", group.sName},
                {"role", group.sRole},
                {"description", group.sDescription},
                {"member_count", group.iMemberCount},
                {"created_at", std::chrono::duration_cast<std::chrono::seconds>(
                                   group.tpCreatedAt.time_since_epoch())
                                   .count()},
            });
          }
          return jsonResponse(200, jArr);
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });

  // POST /api/v1/groups
  CROW_ROUTE(app, "/api/v1/groups").methods("POST"_method)(
      [this](const crow::request& req) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kGroupsCreate);

          auto jBody = nlohmann::json::parse(req.body);
          std::string sName = jBody.value("name", "");
          std::string sRole = jBody.value("role", "");
          std::string sDescription = jBody.value("description", "");

          RequestValidator::validateGroupName(sName);
          RequestValidator::validateRequired(sRole, "role");

          int64_t iId = _grRepo.create(sName, sRole, sDescription);
          return jsonResponse(201, {{"id", iId}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        } catch (const nlohmann::json::exception&) {
          return invalidJsonResponse();
        }
      });

  // GET /api/v1/groups/<int>
  CROW_ROUTE(app, "/api/v1/groups/<int>").methods("GET"_method)(
      [this](const crow::request& req, int iGroupId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kGroupsView);

          auto oGroup = _grRepo.findById(iGroupId);
          if (!oGroup) throw common::NotFoundError("GROUP_NOT_FOUND", "Group not found");

          auto vMembers = _grRepo.listMembers(iGroupId);
          nlohmann::json jMembers = nlohmann::json::array();
          for (const auto& [iUid, sUname] : vMembers) {
            jMembers.push_back({{"id", iUid}, {"username", sUname}});
          }

          return jsonResponse(200, {
              {"id", oGroup->iId},
              {"name", oGroup->sName},
              {"role", oGroup->sRole},
              {"description", oGroup->sDescription},
              {"member_count", oGroup->iMemberCount},
              {"created_at", std::chrono::duration_cast<std::chrono::seconds>(
                                 oGroup->tpCreatedAt.time_since_epoch())
                                 .count()},
              {"members", jMembers},
          });
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });

  // PUT /api/v1/groups/<int>
  CROW_ROUTE(app, "/api/v1/groups/<int>").methods("PUT"_method)(
      [this](const crow::request& req, int iGroupId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kGroupsEdit);

          auto oGroup = _grRepo.findById(iGroupId);
          if (!oGroup) throw common::NotFoundError("GROUP_NOT_FOUND", "Group not found");

          auto jBody = nlohmann::json::parse(req.body);
          std::string sName = jBody.value("name", oGroup->sName);
          std::string sRole = jBody.value("role", oGroup->sRole);
          std::string sDescription = jBody.value("description", oGroup->sDescription);

          RequestValidator::validateGroupName(sName);

          _grRepo.update(iGroupId, sName, sRole, sDescription);
          return jsonResponse(200, {{"message", "Group updated"}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        } catch (const nlohmann::json::exception&) {
          return invalidJsonResponse();
        }
      });

  // DELETE /api/v1/groups/<int>
  CROW_ROUTE(app, "/api/v1/groups/<int>").methods("DELETE"_method)(
      [this](const crow::request& req, int iGroupId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kGroupsDelete);

          _grRepo.deleteGroup(iGroupId);
          return jsonResponse(200, {{"message", "Group deleted"}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });
}

}  // namespace dns::api::routes
