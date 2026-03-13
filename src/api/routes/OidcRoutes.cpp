#include "api/routes/OidcRoutes.hpp"

#include "api/RouteHelpers.hpp"
#include "common/Errors.hpp"
#include "dal/IdpRepository.hpp"
#include "security/FederatedAuthService.hpp"
#include "security/OidcService.hpp"

#include <spdlog/spdlog.h>

#include <nlohmann/json.hpp>

namespace dns::api::routes {

OidcRoutes::OidcRoutes(dns::dal::IdpRepository& irRepo,
                       dns::security::OidcService& osService,
                       dns::security::FederatedAuthService& fasService)
    : _irRepo(irRepo), _osService(osService), _fasService(fasService) {}

OidcRoutes::~OidcRoutes() = default;

void OidcRoutes::registerRoutes(crow::SimpleApp& app) {
  // GET /api/v1/auth/identity-providers — public, list enabled IdPs for login page
  CROW_ROUTE(app, "/api/v1/auth/identity-providers").methods("GET"_method)(
      [this](const crow::request&) -> crow::response {
        try {
          auto vIdps = _irRepo.listEnabled();
          nlohmann::json jArr = nlohmann::json::array();
          for (const auto& idp : vIdps) {
            jArr.push_back({
                {"id", idp.iId},
                {"name", idp.sName},
                {"type", idp.sType},
            });
          }
          return jsonResponse(200, jArr);
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });

  // GET /api/v1/auth/oidc/<int>/login — initiate OIDC flow
  CROW_ROUTE(app, "/api/v1/auth/oidc/<int>/login").methods("GET"_method)(
      [this](const crow::request&, int iIdpId) -> crow::response {
        try {
          auto oIdp = _irRepo.findById(iIdpId);
          if (!oIdp.has_value() || !oIdp->bIsEnabled || oIdp->sType != "oidc") {
            throw common::NotFoundError("IDP_NOT_FOUND", "OIDC identity provider not found");
          }

          std::string sIssuerUrl = oIdp->jConfig.value("issuer_url", "");
          std::string sClientId = oIdp->jConfig.value("client_id", "");
          std::string sRedirectUri = oIdp->jConfig.value("redirect_uri", "");
          std::string sGroupsClaim = oIdp->jConfig.value("groups_claim", "groups");

          // Build scopes from config array
          std::string sScopes = "openid email profile";
          if (oIdp->jConfig.contains("scopes") && oIdp->jConfig["scopes"].is_array()) {
            sScopes.clear();
            for (const auto& scope : oIdp->jConfig["scopes"]) {
              if (!sScopes.empty()) sScopes += " ";
              sScopes += scope.get<std::string>();
            }
          }

          // Discover endpoints
          auto odDiscovery = _osService.discover(sIssuerUrl);

          // Generate PKCE
          auto [sVerifier, sChallenge] = dns::security::OidcService::generatePkce();
          auto sState = dns::security::OidcService::generateState();

          // Store auth state
          dns::security::OidcAuthState oaState;
          oaState.sCodeVerifier = sVerifier;
          oaState.iIdpId = iIdpId;
          oaState.bIsTestMode = false;
          oaState.tpCreatedAt = std::chrono::system_clock::now();
          _osService.storeAuthState(sState, oaState);

          // Build authorization URL
          std::string sUrl = dns::security::OidcService::buildAuthorizationUrl(
              odDiscovery.sAuthorizationEndpoint, sClientId, sRedirectUri,
              sScopes, sState, sChallenge);

          // Return 302 redirect
          crow::response resp(302);
          resp.set_header("Location", sUrl);
          return resp;
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });

  // GET /api/v1/auth/oidc/<int>/callback — handle IdP redirect
  CROW_ROUTE(app, "/api/v1/auth/oidc/<int>/callback").methods("GET"_method)(
      [this](const crow::request& req, int iIdpId) -> crow::response {
        try {
          // Extract query parameters
          auto sCode = req.url_params.get("code");
          auto sState = req.url_params.get("state");

          if (!sCode || !sState) {
            throw common::ValidationError("MISSING_PARAMS",
                                          "Missing code or state parameter");
          }

          // Consume auth state
          auto oState = _osService.consumeAuthState(sState);
          if (!oState.has_value()) {
            throw common::AuthenticationError("INVALID_STATE",
                                              "Invalid or expired state parameter");
          }

          if (oState->iIdpId != iIdpId) {
            throw common::AuthenticationError("STATE_MISMATCH",
                                              "State IdP ID does not match URL");
          }

          // Load IdP (includes decrypted secret)
          auto oIdp = _irRepo.findById(iIdpId);
          if (!oIdp.has_value()) {
            throw common::NotFoundError("IDP_NOT_FOUND", "Identity provider not found");
          }

          std::string sIssuerUrl = oIdp->jConfig.value("issuer_url", "");
          std::string sClientId = oIdp->jConfig.value("client_id", "");
          std::string sRedirectUri = oIdp->jConfig.value("redirect_uri", "");
          std::string sGroupsClaim = oIdp->jConfig.value("groups_claim", "groups");

          // Discover endpoints
          auto odDiscovery = _osService.discover(sIssuerUrl);

          // Exchange code for tokens
          auto jTokens = _osService.exchangeCode(
              odDiscovery.sTokenEndpoint, sCode, sClientId,
              oIdp->sDecryptedSecret, sRedirectUri, oState->sCodeVerifier);

          std::string sIdToken = jTokens.value("id_token", "");
          if (sIdToken.empty()) {
            throw common::AuthenticationError("NO_ID_TOKEN",
                                              "No id_token in token response");
          }

          // Validate ID token
          auto jPayload = _osService.validateIdToken(
              sIdToken, odDiscovery.sJwksUri, odDiscovery.sIssuer, sClientId);

          // Extract claims
          std::string sSub = jPayload.value("sub", "");
          std::string sEmail = jPayload.value("email", "");
          std::string sUsername = jPayload.value("preferred_username", "");
          if (sUsername.empty()) {
            sUsername = jPayload.value("email", sSub);
          }

          // Extract groups
          std::vector<std::string> vGroups;
          if (jPayload.contains(sGroupsClaim) && jPayload[sGroupsClaim].is_array()) {
            for (const auto& g : jPayload[sGroupsClaim]) {
              vGroups.push_back(g.get<std::string>());
            }
          }

          // Test mode: return raw claims
          if (oState->bIsTestMode) {
            nlohmann::json jResult = {
                {"subject", sSub},
                {"email", sEmail},
                {"username", sUsername},
                {"groups", vGroups},
                {"all_claims", jPayload},
            };
            return jsonResponse(200, jResult);
          }

          // Process federated login
          auto lr = _fasService.processFederatedLogin(
              "oidc", sSub, sUsername, sEmail, vGroups,
              oIdp->jGroupMappings, oIdp->iDefaultGroupId);

          // Redirect to SPA with token
          crow::response resp(302);
          resp.set_header("Location", "/auth/callback?token=" + lr.sToken);
          return resp;
        } catch (const common::AppError& e) {
          spdlog::error("OIDC callback error: {}", e.what());
          // Redirect to login with error
          crow::response resp(302);
          resp.set_header("Location", "/login?error=auth_failed");
          return resp;
        }
      });
}

}  // namespace dns::api::routes
