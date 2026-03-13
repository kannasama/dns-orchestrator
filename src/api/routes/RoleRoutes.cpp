#include "api/routes/RoleRoutes.hpp"

#include "api/AuthMiddleware.hpp"
#include "api/RequestValidator.hpp"
#include "api/RouteHelpers.hpp"
#include "common/Errors.hpp"
#include "common/Permissions.hpp"
#include "dal/RoleRepository.hpp"

#include <nlohmann/json.hpp>

namespace dns::api::routes {
using namespace dns::common;

RoleRoutes::RoleRoutes(dns::dal::RoleRepository& rrRepo,
                       const dns::api::AuthMiddleware& amMiddleware)
    : _rrRepo(rrRepo), _amMiddleware(amMiddleware) {}

RoleRoutes::~RoleRoutes() = default;

void RoleRoutes::registerRoutes(crow::SimpleApp& app) {
  // GET /api/v1/roles
  CROW_ROUTE(app, "/api/v1/roles").methods("GET"_method)(
      [this](const crow::request& req) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kRolesView);

          auto vRoles = _rrRepo.listAll();
          nlohmann::json jArr = nlohmann::json::array();
          for (const auto& role : vRoles) {
            jArr.push_back({
                {"id", role.iId},
                {"name", role.sName},
                {"description", role.sDescription},
                {"is_system", role.bIsSystem},
                {"created_at", role.sCreatedAt},
            });
          }
          return jsonResponse(200, jArr);
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });

  // POST /api/v1/roles
  CROW_ROUTE(app, "/api/v1/roles").methods("POST"_method)(
      [this](const crow::request& req) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kRolesCreate);

          auto jBody = nlohmann::json::parse(req.body);
          std::string sName = jBody.value("name", "");
          std::string sDescription = jBody.value("description", "");

          RequestValidator::validateRequired(sName, "name");

          int64_t iId = _rrRepo.create(sName, sDescription);

          // Set permissions if provided
          if (jBody.contains("permissions") && jBody["permissions"].is_array()) {
            std::vector<std::string> vPerms;
            for (const auto& p : jBody["permissions"]) {
              std::string sPerm = p.get<std::string>();
              bool bValid = false;
              for (const auto& kp : Permissions::kAllPermissions) {
                if (sPerm == kp) { bValid = true; break; }
              }
              if (!bValid) {
                throw common::ValidationError("INVALID_PERMISSION",
                                               "Unknown permission: " + sPerm);
              }
              vPerms.push_back(sPerm);
            }
            _rrRepo.setPermissions(iId, vPerms);
          }

          return jsonResponse(201, {{"id", iId}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        } catch (const nlohmann::json::exception&) {
          return invalidJsonResponse();
        }
      });

  // GET /api/v1/roles/<int>
  CROW_ROUTE(app, "/api/v1/roles/<int>").methods("GET"_method)(
      [this](const crow::request& req, int iRoleId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kRolesView);

          auto oRole = _rrRepo.findById(iRoleId);
          if (!oRole) throw common::NotFoundError("ROLE_NOT_FOUND", "Role not found");

          auto vPerms = _rrRepo.getPermissions(iRoleId);
          nlohmann::json jPerms = nlohmann::json::array();
          for (const auto& sPerm : vPerms) jPerms.push_back(sPerm);

          return jsonResponse(200, {
              {"id", oRole->iId},
              {"name", oRole->sName},
              {"description", oRole->sDescription},
              {"is_system", oRole->bIsSystem},
              {"permissions", jPerms},
              {"created_at", oRole->sCreatedAt},
          });
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });

  // PUT /api/v1/roles/<int>
  CROW_ROUTE(app, "/api/v1/roles/<int>").methods("PUT"_method)(
      [this](const crow::request& req, int iRoleId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kRolesEdit);

          auto oRole = _rrRepo.findById(iRoleId);
          if (!oRole) throw common::NotFoundError("ROLE_NOT_FOUND", "Role not found");

          auto jBody = nlohmann::json::parse(req.body);
          std::string sName = jBody.value("name", oRole->sName);
          std::string sDescription = jBody.value("description", oRole->sDescription);

          _rrRepo.update(iRoleId, sName, sDescription);
          return jsonResponse(200, {{"message", "Role updated"}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        } catch (const nlohmann::json::exception&) {
          return invalidJsonResponse();
        }
      });

  // DELETE /api/v1/roles/<int>
  CROW_ROUTE(app, "/api/v1/roles/<int>").methods("DELETE"_method)(
      [this](const crow::request& req, int iRoleId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kRolesDelete);

          _rrRepo.deleteRole(iRoleId);
          return jsonResponse(200, {{"message", "Role deleted"}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });

  // GET /api/v1/roles/<int>/permissions
  CROW_ROUTE(app, "/api/v1/roles/<int>/permissions").methods("GET"_method)(
      [this](const crow::request& req, int iRoleId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kRolesView);

          auto oRole = _rrRepo.findById(iRoleId);
          if (!oRole) throw common::NotFoundError("ROLE_NOT_FOUND", "Role not found");

          auto vPerms = _rrRepo.getPermissions(iRoleId);
          nlohmann::json jPerms = nlohmann::json::array();
          for (const auto& sPerm : vPerms) jPerms.push_back(sPerm);

          return jsonResponse(200, jPerms);
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });

  // PUT /api/v1/roles/<int>/permissions
  CROW_ROUTE(app, "/api/v1/roles/<int>/permissions").methods("PUT"_method)(
      [this](const crow::request& req, int iRoleId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kRolesEdit);

          auto oRole = _rrRepo.findById(iRoleId);
          if (!oRole) throw common::NotFoundError("ROLE_NOT_FOUND", "Role not found");

          auto jBody = nlohmann::json::parse(req.body);
          auto jPerms = jBody.value("permissions", nlohmann::json::array());
          std::vector<std::string> vPerms;
          for (const auto& p : jPerms) {
            std::string sPerm = p.get<std::string>();
            bool bValid = false;
            for (const auto& kp : Permissions::kAllPermissions) {
              if (sPerm == kp) { bValid = true; break; }
            }
            if (!bValid) {
              throw common::ValidationError("INVALID_PERMISSION",
                                             "Unknown permission: " + sPerm);
            }
            vPerms.push_back(sPerm);
          }
          _rrRepo.setPermissions(iRoleId, vPerms);
          return jsonResponse(200, {{"message", "Permissions updated"}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        } catch (const nlohmann::json::exception&) {
          return invalidJsonResponse();
        }
      });

  // GET /api/v1/permissions
  CROW_ROUTE(app, "/api/v1/permissions").methods("GET"_method)(
      [this](const crow::request& req) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kRolesView);

          nlohmann::json jCategories = nlohmann::json::array();
          struct Category {
            std::string sName;
            std::string sPrefix;
          };
          std::vector<Category> vCategories = {
              {"Zones", "zones."}, {"Records", "records."},
              {"Providers", "providers."}, {"Views", "views."},
              {"Variables", "variables."}, {"Git Repos", "repos."},
              {"Audit", "audit."}, {"Users", "users."},
              {"Groups", "groups."}, {"Roles", "roles."},
              {"Settings", "settings."}, {"Backup", "backup."},
          };
          for (const auto& cat : vCategories) {
            nlohmann::json jPerms = nlohmann::json::array();
            for (const auto& perm : Permissions::kAllPermissions) {
              if (std::string(perm).starts_with(cat.sPrefix)) {
                jPerms.push_back(std::string(perm));
              }
            }
            jCategories.push_back({{"name", cat.sName}, {"permissions", jPerms}});
          }
          return jsonResponse(200, jCategories);
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });
}

}  // namespace dns::api::routes
