#include "api/routes/GitRepoRoutes.hpp"

#include "api/AuthMiddleware.hpp"
#include "api/RequestValidator.hpp"
#include "api/RouteHelpers.hpp"
#include "common/Errors.hpp"
#include "common/Permissions.hpp"
#include "dal/GitRepoRepository.hpp"
#include "gitops/GitRepoManager.hpp"

#include <nlohmann/json.hpp>

namespace dns::api::routes {
using namespace dns::common;

GitRepoRoutes::GitRepoRoutes(dns::dal::GitRepoRepository& grRepo,
                             const dns::api::AuthMiddleware& amMiddleware,
                             dns::gitops::GitRepoManager& grmManager)
    : _grRepo(grRepo), _amMiddleware(amMiddleware), _grmManager(grmManager) {}

GitRepoRoutes::~GitRepoRoutes() = default;

void GitRepoRoutes::registerRoutes(crow::SimpleApp& app) {
  // GET /api/v1/git-repos — list all repos
  CROW_ROUTE(app, "/api/v1/git-repos").methods("GET"_method)(
      [this](const crow::request& req) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kReposView);

          auto vRepos = _grRepo.listAll();
          nlohmann::json jArr = nlohmann::json::array();
          for (const auto& repo : vRepos) {
            jArr.push_back({
                {"id", repo.iId},
                {"name", repo.sName},
                {"remote_url", repo.sRemoteUrl},
                {"auth_type", repo.sAuthType},
                {"has_credentials", false},  // listAll doesn't decrypt
                {"default_branch", repo.sDefaultBranch},
                {"local_path", repo.sLocalPath},
                {"is_enabled", repo.bIsEnabled},
                {"last_sync_at", repo.sLastSyncAt.empty()
                                     ? nlohmann::json(nullptr) : nlohmann::json(repo.sLastSyncAt)},
                {"last_sync_status", repo.sLastSyncStatus.empty()
                                         ? nlohmann::json(nullptr) : nlohmann::json(repo.sLastSyncStatus)},
                {"last_sync_error", repo.sLastSyncError.empty()
                                        ? nlohmann::json(nullptr) : nlohmann::json(repo.sLastSyncError)},
                {"created_at", repo.sCreatedAt},
                {"updated_at", repo.sUpdatedAt},
            });
          }
          return jsonResponse(200, jArr);
        } catch (const AppError& e) {
          return errorResponse(e);
        }
      });

  // POST /api/v1/git-repos — create repo
  CROW_ROUTE(app, "/api/v1/git-repos").methods("POST"_method)(
      [this](const crow::request& req) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kReposCreate);

          auto jBody = nlohmann::json::parse(req.body, nullptr, false);
          if (jBody.is_discarded()) return invalidJsonResponse();

          std::string sName = jBody.value("name", "");
          std::string sRemoteUrl = jBody.value("remote_url", "");
          std::string sAuthType = jBody.value("auth_type", "none");
          std::string sCredentials = jBody.value("credentials", "");
          std::string sDefaultBranch = jBody.value("default_branch", "main");
          std::string sLocalPath = jBody.value("local_path", "");
          std::string sKnownHosts = jBody.value("known_hosts", "");

          RequestValidator::validateGitRepoName(sName);
          RequestValidator::validateGitRemoteUrl(sRemoteUrl);
          RequestValidator::validateGitAuthType(sAuthType);

          int64_t iId = _grRepo.create(sName, sRemoteUrl, sAuthType, sCredentials,
                                       sDefaultBranch, sLocalPath, sKnownHosts);

          // Hot-reload the mirror
          _grmManager.reloadRepo(iId);

          return jsonResponse(201, {{"id", iId}, {"name", sName}});
        } catch (const AppError& e) {
          return errorResponse(e);
        }
      });

  // GET /api/v1/git-repos/<int> — get repo by ID (credentials masked)
  CROW_ROUTE(app, "/api/v1/git-repos/<int>").methods("GET"_method)(
      [this](const crow::request& req, int iId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kReposView);

          auto oRepo = _grRepo.findById(iId);
          if (!oRepo) {
            throw NotFoundError("GIT_REPO_NOT_FOUND",
                                "Git repo " + std::to_string(iId) + " not found");
          }

          nlohmann::json j = {
              {"id", oRepo->iId},
              {"name", oRepo->sName},
              {"remote_url", oRepo->sRemoteUrl},
              {"auth_type", oRepo->sAuthType},
              {"has_credentials", !oRepo->sDecryptedCredentials.empty()},
              {"default_branch", oRepo->sDefaultBranch},
              {"local_path", oRepo->sLocalPath},
              {"known_hosts", oRepo->sKnownHosts},
              {"is_enabled", oRepo->bIsEnabled},
              {"last_sync_at", oRepo->sLastSyncAt.empty()
                                   ? nlohmann::json(nullptr) : nlohmann::json(oRepo->sLastSyncAt)},
              {"last_sync_status", oRepo->sLastSyncStatus.empty()
                                       ? nlohmann::json(nullptr) : nlohmann::json(oRepo->sLastSyncStatus)},
              {"last_sync_error", oRepo->sLastSyncError.empty()
                                      ? nlohmann::json(nullptr) : nlohmann::json(oRepo->sLastSyncError)},
              {"created_at", oRepo->sCreatedAt},
              {"updated_at", oRepo->sUpdatedAt},
          };
          return jsonResponse(200, j);
        } catch (const AppError& e) {
          return errorResponse(e);
        }
      });

  // PUT /api/v1/git-repos/<int> — update repo
  CROW_ROUTE(app, "/api/v1/git-repos/<int>").methods("PUT"_method)(
      [this](const crow::request& req, int iId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kReposEdit);

          auto jBody = nlohmann::json::parse(req.body, nullptr, false);
          if (jBody.is_discarded()) return invalidJsonResponse();

          std::string sName = jBody.value("name", "");
          std::string sRemoteUrl = jBody.value("remote_url", "");
          std::string sAuthType = jBody.value("auth_type", "none");
          std::string sCredentials = jBody.value("credentials", "");
          std::string sDefaultBranch = jBody.value("default_branch", "main");
          std::string sLocalPath = jBody.value("local_path", "");
          std::string sKnownHosts = jBody.value("known_hosts", "");
          bool bIsEnabled = jBody.value("is_enabled", true);

          RequestValidator::validateGitRepoName(sName);
          RequestValidator::validateGitRemoteUrl(sRemoteUrl);
          RequestValidator::validateGitAuthType(sAuthType);

          _grRepo.update(iId, sName, sRemoteUrl, sAuthType, sCredentials,
                         sDefaultBranch, sLocalPath, sKnownHosts, bIsEnabled);

          // Hot-reload the mirror
          _grmManager.reloadRepo(iId);

          return jsonResponse(200, {{"message", "Git repo updated"}});
        } catch (const AppError& e) {
          return errorResponse(e);
        }
      });

  // DELETE /api/v1/git-repos/<int> — delete repo
  CROW_ROUTE(app, "/api/v1/git-repos/<int>").methods("DELETE"_method)(
      [this](const crow::request& req, int iId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kReposDelete);

          _grRepo.deleteById(iId);
          _grmManager.removeRepo(iId);

          return jsonResponse(200, {{"message", "Git repo deleted"}});
        } catch (const AppError& e) {
          return errorResponse(e);
        }
      });

  // POST /api/v1/git-repos/<int>/test — test connection
  CROW_ROUTE(app, "/api/v1/git-repos/<int>/test").methods("POST"_method)(
      [this](const crow::request& req, int iId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kReposEdit);

          std::string sError = _grmManager.testConnection(iId);
          if (sError.empty()) {
            return jsonResponse(200, {{"success", true}, {"message", "Connection successful"}});
          } else {
            return jsonResponse(200, {{"success", false}, {"message", sError}});
          }
        } catch (const AppError& e) {
          return errorResponse(e);
        }
      });

  // POST /api/v1/git-repos/<int>/sync — manual pull
  CROW_ROUTE(app, "/api/v1/git-repos/<int>/sync").methods("POST"_method)(
      [this](const crow::request& req, int iId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kReposEdit);

          _grmManager.pullRepo(iId);
          return jsonResponse(200, {{"message", "Sync completed"}});
        } catch (const AppError& e) {
          return errorResponse(e);
        }
      });
}

}  // namespace dns::api::routes
