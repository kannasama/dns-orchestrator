#include "api/routes/UserRoutes.hpp"

#include "api/AuthMiddleware.hpp"
#include "api/RequestValidator.hpp"
#include "api/RouteHelpers.hpp"
#include "common/Errors.hpp"
#include "common/Permissions.hpp"
#include "dal/GroupRepository.hpp"
#include "dal/UserRepository.hpp"
#include "security/CryptoService.hpp"

#include <nlohmann/json.hpp>

namespace dns::api::routes {
using namespace dns::common;

UserRoutes::UserRoutes(dns::dal::UserRepository& urRepo, dns::dal::GroupRepository& grRepo,
                       const dns::api::AuthMiddleware& amMiddleware)
    : _urRepo(urRepo), _grRepo(grRepo), _amMiddleware(amMiddleware) {}

UserRoutes::~UserRoutes() = default;

void UserRoutes::registerRoutes(crow::SimpleApp& app) {
  // GET /api/v1/users
  CROW_ROUTE(app, "/api/v1/users").methods("GET"_method)(
      [this](const crow::request& req) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kUsersView);

          auto vUsers = _urRepo.listAll();
          nlohmann::json jArr = nlohmann::json::array();
          for (const auto& user : vUsers) {
            auto vGroups = _urRepo.listGroupsForUser(user.iId);
            nlohmann::json jGroups = nlohmann::json::array();
            for (const auto& [iGid, sGname] : vGroups) {
              jGroups.push_back({{"id", iGid}, {"name", sGname}});
            }
            jArr.push_back({
                {"id", user.iId},
                {"username", user.sUsername},
                {"email", user.sEmail},
                {"auth_method", user.sAuthMethod},
                {"is_active", user.bIsActive},
                {"force_password_change", user.bForcePasswordChange},
                {"groups", jGroups},
            });
          }
          return jsonResponse(200, jArr);
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });

  // POST /api/v1/users
  CROW_ROUTE(app, "/api/v1/users").methods("POST"_method)(
      [this](const crow::request& req) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kUsersCreate);

          auto jBody = nlohmann::json::parse(req.body);
          std::string sUsername = jBody.value("username", "");
          std::string sPassword = jBody.value("password", "");
          std::string sEmail = jBody.value("email", "");

          RequestValidator::validateUsername(sUsername);
          RequestValidator::validatePassword(sPassword);

          std::string sHash = dns::security::CryptoService::hashPassword(sPassword);
          int64_t iUserId = _urRepo.create(sUsername, sEmail, sHash);

          bool bForceChange = jBody.value("force_password_change", false);
          if (bForceChange) {
            _urRepo.setForcePasswordChange(iUserId, true);
          }

          // Add to groups if specified (with role assignment)
          if (jBody.contains("group_memberships") && jBody["group_memberships"].is_array()) {
            for (const auto& jMember : jBody["group_memberships"]) {
              int64_t iGid = jMember.at("group_id").get<int64_t>();
              int64_t iRoleId = jMember.at("role_id").get<int64_t>();
              std::string sScopeType = jMember.value("scope_type", "");
              int64_t iScopeId = jMember.value("scope_id", 0);
              _urRepo.addToGroup(iUserId, iGid, iRoleId, sScopeType, iScopeId);
            }
          }

          return jsonResponse(201, {{"id", iUserId}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        } catch (const nlohmann::json::exception&) {
          return invalidJsonResponse();
        }
      });

  // GET /api/v1/users/<int>
  CROW_ROUTE(app, "/api/v1/users/<int>").methods("GET"_method)(
      [this](const crow::request& req, int iUserId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kUsersView);

          auto oUser = _urRepo.findById(iUserId);
          if (!oUser) throw common::NotFoundError("USER_NOT_FOUND", "User not found");

          auto vGroups = _urRepo.listGroupsForUser(iUserId);
          nlohmann::json jGroups = nlohmann::json::array();
          for (const auto& [iGid, sGname] : vGroups) {
            jGroups.push_back({{"id", iGid}, {"name", sGname}});
          }

          return jsonResponse(200, {
              {"id", oUser->iId},
              {"username", oUser->sUsername},
              {"email", oUser->sEmail},
              {"auth_method", oUser->sAuthMethod},
              {"is_active", oUser->bIsActive},
              {"force_password_change", oUser->bForcePasswordChange},
              {"groups", jGroups},
          });
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });

  // PUT /api/v1/users/<int>
  CROW_ROUTE(app, "/api/v1/users/<int>").methods("PUT"_method)(
      [this](const crow::request& req, int iUserId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kUsersEdit);

          auto oUser = _urRepo.findById(iUserId);
          if (!oUser) throw common::NotFoundError("USER_NOT_FOUND", "User not found");

          auto jBody = nlohmann::json::parse(req.body);
          std::string sEmail = jBody.value("email", oUser->sEmail);
          bool bIsActive = jBody.value("is_active", oUser->bIsActive);

          _urRepo.update(iUserId, sEmail, bIsActive);

          // Sync group memberships: remove all, then re-add
          if (jBody.contains("group_memberships") && jBody["group_memberships"].is_array()) {
            auto vCurrentGroups = _urRepo.listGroupsForUser(iUserId);
            for (const auto& [iGid, sGname] : vCurrentGroups) {
              _urRepo.removeFromGroup(iUserId, iGid);
            }
            for (const auto& jMember : jBody["group_memberships"]) {
              int64_t iGid = jMember.at("group_id").get<int64_t>();
              int64_t iRoleId = jMember.at("role_id").get<int64_t>();
              std::string sScopeType = jMember.value("scope_type", "");
              int64_t iScopeId = jMember.value("scope_id", 0);
              _urRepo.addToGroup(iUserId, iGid, iRoleId, sScopeType, iScopeId);
            }
          }

          return jsonResponse(200, {{"message", "User updated"}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        } catch (const nlohmann::json::exception&) {
          return invalidJsonResponse();
        }
      });

  // DELETE /api/v1/users/<int>
  CROW_ROUTE(app, "/api/v1/users/<int>").methods("DELETE"_method)(
      [this](const crow::request& req, int iUserId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kUsersDelete);

          _urRepo.deactivate(iUserId);
          return jsonResponse(200, {{"message", "User deactivated"}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });

  // POST /api/v1/users/<int>/reset-password
  CROW_ROUTE(app, "/api/v1/users/<int>/reset-password").methods("POST"_method)(
      [this](const crow::request& req, int iUserId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kUsersEdit);

          auto oUser = _urRepo.findById(iUserId);
          if (!oUser) throw common::NotFoundError("USER_NOT_FOUND", "User not found");

          auto jBody = nlohmann::json::parse(req.body);
          std::string sNewPassword = jBody.value("password", "");
          RequestValidator::validatePassword(sNewPassword);

          std::string sHash = dns::security::CryptoService::hashPassword(sNewPassword);
          _urRepo.updatePassword(iUserId, sHash);
          _urRepo.setForcePasswordChange(iUserId, true);

          return jsonResponse(200, {{"message", "Password reset successfully"}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        } catch (const nlohmann::json::exception&) {
          return invalidJsonResponse();
        }
      });
}

}  // namespace dns::api::routes
