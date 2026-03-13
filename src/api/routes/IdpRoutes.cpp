#include "api/routes/IdpRoutes.hpp"

#include "api/AuthMiddleware.hpp"
#include "api/RouteHelpers.hpp"
#include "common/Errors.hpp"
#include "common/Permissions.hpp"
#include "dal/IdpRepository.hpp"
#include "security/OidcService.hpp"
#include "security/SamlService.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

namespace dns::api::routes {
using namespace dns::common;

IdpRoutes::IdpRoutes(dns::dal::IdpRepository& irRepo,
                     const dns::api::AuthMiddleware& amMiddleware,
                     dns::security::OidcService& osService,
                     dns::security::SamlService& ssService)
    : _irRepo(irRepo), _amMiddleware(amMiddleware),
      _osService(osService), _ssService(ssService) {}

IdpRoutes::~IdpRoutes() = default;

void IdpRoutes::registerRoutes(crow::SimpleApp& app) {
  // GET /api/v1/identity-providers — list all IdPs
  CROW_ROUTE(app, "/api/v1/identity-providers").methods("GET"_method)(
      [this](const crow::request& req) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kSettingsView);

          auto vIdps = _irRepo.listAll();
          nlohmann::json jArr = nlohmann::json::array();
          for (const auto& idp : vIdps) {
            jArr.push_back({
                {"id", idp.iId},
                {"name", idp.sName},
                {"type", idp.sType},
                {"is_enabled", idp.bIsEnabled},
                {"config", idp.jConfig},
                {"has_secret", !idp.sDecryptedSecret.empty()},
                {"group_mappings", idp.jGroupMappings},
                {"default_group_id", idp.iDefaultGroupId > 0
                                         ? nlohmann::json(idp.iDefaultGroupId)
                                         : nlohmann::json(nullptr)},
                {"created_at", idp.sCreatedAt},
                {"updated_at", idp.sUpdatedAt},
            });
          }
          return jsonResponse(200, jArr);
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });

  // POST /api/v1/identity-providers — create IdP
  CROW_ROUTE(app, "/api/v1/identity-providers").methods("POST"_method)(
      [this](const crow::request& req) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kSettingsEdit);

          auto jBody = nlohmann::json::parse(req.body, nullptr, false);
          if (jBody.is_discarded()) return invalidJsonResponse();

          std::string sName = jBody.value("name", "");
          std::string sType = jBody.value("type", "");
          if (sName.empty()) {
            throw ValidationError("NAME_REQUIRED", "Name is required");
          }
          if (sType != "oidc" && sType != "saml") {
            throw ValidationError("INVALID_TYPE", "Type must be 'oidc' or 'saml'");
          }

          nlohmann::json jConfig = jBody.value("config", nlohmann::json::object());
          std::string sSecret = jBody.value("client_secret", "");
          nlohmann::json jMappings = jBody.contains("group_mappings")
                                         ? jBody["group_mappings"]
                                         : nlohmann::json{};
          int64_t iDefaultGroupId = jBody.value("default_group_id", static_cast<int64_t>(0));

          // Validate type-specific config
          if (sType == "oidc") {
            if (!jConfig.contains("issuer_url") || !jConfig.contains("client_id")) {
              throw ValidationError("OIDC_CONFIG_INVALID",
                                    "OIDC config requires issuer_url and client_id");
            }
          } else if (sType == "saml") {
            if (!jConfig.contains("entity_id") || !jConfig.contains("sso_url") ||
                !jConfig.contains("certificate")) {
              throw ValidationError("SAML_CONFIG_INVALID",
                                    "SAML config requires entity_id, sso_url, and certificate");
            }
          }

          int64_t iId = _irRepo.create(sName, sType, jConfig, sSecret, jMappings,
                                        iDefaultGroupId);

          return jsonResponse(201, {{"id", iId}, {"name", sName}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });

  // GET /api/v1/identity-providers/<int> — get single IdP
  CROW_ROUTE(app, "/api/v1/identity-providers/<int>").methods("GET"_method)(
      [this](const crow::request& req, int iId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kSettingsView);

          auto oIdp = _irRepo.findById(iId);
          if (!oIdp.has_value()) {
            throw NotFoundError("IDP_NOT_FOUND", "Identity provider not found");
          }

          nlohmann::json jResult = {
              {"id", oIdp->iId},
              {"name", oIdp->sName},
              {"type", oIdp->sType},
              {"is_enabled", oIdp->bIsEnabled},
              {"config", oIdp->jConfig},
              {"has_secret", !oIdp->sDecryptedSecret.empty()},
              {"group_mappings", oIdp->jGroupMappings},
              {"default_group_id", oIdp->iDefaultGroupId > 0
                                       ? nlohmann::json(oIdp->iDefaultGroupId)
                                       : nlohmann::json(nullptr)},
              {"created_at", oIdp->sCreatedAt},
              {"updated_at", oIdp->sUpdatedAt},
          };
          return jsonResponse(200, jResult);
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });

  // PUT /api/v1/identity-providers/<int> — update IdP
  CROW_ROUTE(app, "/api/v1/identity-providers/<int>").methods("PUT"_method)(
      [this](const crow::request& req, int iId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kSettingsEdit);

          auto jBody = nlohmann::json::parse(req.body, nullptr, false);
          if (jBody.is_discarded()) return invalidJsonResponse();

          std::string sName = jBody.value("name", "");
          if (sName.empty()) {
            throw ValidationError("NAME_REQUIRED", "Name is required");
          }

          bool bIsEnabled = jBody.value("is_enabled", true);
          nlohmann::json jConfig = jBody.value("config", nlohmann::json::object());
          std::string sSecret = jBody.value("client_secret", "");
          nlohmann::json jMappings = jBody.contains("group_mappings")
                                         ? jBody["group_mappings"]
                                         : nlohmann::json{};
          int64_t iDefaultGroupId = jBody.value("default_group_id", static_cast<int64_t>(0));

          _irRepo.update(iId, sName, bIsEnabled, jConfig, sSecret, jMappings,
                         iDefaultGroupId);

          return jsonResponse(200, {{"message", "Identity provider updated"}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });

  // DELETE /api/v1/identity-providers/<int> — delete IdP
  CROW_ROUTE(app, "/api/v1/identity-providers/<int>").methods("DELETE"_method)(
      [this](const crow::request& req, int iId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kSettingsEdit);

          _irRepo.deleteIdp(iId);
          return jsonResponse(200, {{"message", "Identity provider deleted"}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });

  // ── Task 12: Test diagnostic route ───────────────────────────────────────

  // GET /api/v1/identity-providers/<int>/test — initiate test auth flow
  CROW_ROUTE(app, "/api/v1/identity-providers/<int>/test").methods("GET"_method)(
      [this](const crow::request& req, int iId) -> crow::response {
        try {
          auto rcCtx = authenticate(_amMiddleware, req);
          requirePermission(rcCtx, Permissions::kSettingsEdit);

          auto oIdp = _irRepo.findById(iId);
          if (!oIdp.has_value()) {
            throw NotFoundError("IDP_NOT_FOUND", "Identity provider not found");
          }

          std::string sRedirectUrl;

          if (oIdp->sType == "oidc") {
            std::string sIssuerUrl = oIdp->jConfig.value("issuer_url", "");
            std::string sClientId = oIdp->jConfig.value("client_id", "");
            std::string sRedirectUri = oIdp->jConfig.value("redirect_uri", "");

            std::string sScopes = "openid email profile";
            if (oIdp->jConfig.contains("scopes") && oIdp->jConfig["scopes"].is_array()) {
              sScopes.clear();
              for (const auto& scope : oIdp->jConfig["scopes"]) {
                if (!sScopes.empty()) sScopes += " ";
                sScopes += scope.get<std::string>();
              }
            }

            auto odDiscovery = _osService.discover(sIssuerUrl);
            auto [sVerifier, sChallenge] = dns::security::OidcService::generatePkce();
            auto sState = dns::security::OidcService::generateState();

            dns::security::OidcAuthState oaState;
            oaState.sCodeVerifier = sVerifier;
            oaState.iIdpId = iId;
            oaState.bIsTestMode = true;
            oaState.tpCreatedAt = std::chrono::system_clock::now();
            _osService.storeAuthState(sState, oaState);

            sRedirectUrl = dns::security::OidcService::buildAuthorizationUrl(
                odDiscovery.sAuthorizationEndpoint, sClientId, sRedirectUri,
                sScopes, sState, sChallenge);

          } else if (oIdp->sType == "saml") {
            std::string sSpEntityId = oIdp->jConfig.value("entity_id", "");
            std::string sSsoUrl = oIdp->jConfig.value("sso_url", "");
            std::string sAcsUrl = oIdp->jConfig.value("assertion_consumer_service_url", "");

            std::string sAuthnRequest = _ssService.generateAuthnRequest(
                sSpEntityId, sAcsUrl, sSsoUrl);

            std::string sRequestId;
            auto iIdStart = sAuthnRequest.find("ID=\"");
            if (iIdStart != std::string::npos) {
              iIdStart += 4;
              auto iIdEnd = sAuthnRequest.find('"', iIdStart);
              if (iIdEnd != std::string::npos) {
                sRequestId = sAuthnRequest.substr(iIdStart, iIdEnd - iIdStart);
              }
            }

            auto sRelayState = dns::security::OidcService::generateState();
            dns::security::SamlAuthState saState;
            saState.iIdpId = iId;
            saState.sRequestId = sRequestId;
            saState.bIsTestMode = true;
            saState.tpCreatedAt = std::chrono::system_clock::now();
            _ssService.storeAuthState(sRelayState, saState);

            sRedirectUrl = _ssService.buildRedirectUrl(sSsoUrl, sAuthnRequest, sRelayState);
          } else {
            throw ValidationError("INVALID_TYPE", "Unknown IdP type: " + oIdp->sType);
          }

          return jsonResponse(200, {{"redirect_url", sRedirectUrl}});
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });
}

}  // namespace dns::api::routes
