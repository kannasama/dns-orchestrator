#include "api/routes/SamlRoutes.hpp"

#include "api/RouteHelpers.hpp"
#include "common/Errors.hpp"
#include "dal/IdpRepository.hpp"
#include "security/FederatedAuthService.hpp"
#include "security/OidcService.hpp"
#include "security/SamlService.hpp"

#include <spdlog/spdlog.h>

#include <nlohmann/json.hpp>

namespace dns::api::routes {

SamlRoutes::SamlRoutes(dns::dal::IdpRepository& irRepo,
                       dns::security::SamlService& ssService,
                       dns::security::FederatedAuthService& fasService)
    : _irRepo(irRepo), _ssService(ssService), _fasService(fasService) {}

SamlRoutes::~SamlRoutes() = default;

void SamlRoutes::registerRoutes(crow::SimpleApp& app) {
  // GET /api/v1/auth/saml/<int>/login — initiate SAML flow
  CROW_ROUTE(app, "/api/v1/auth/saml/<int>/login").methods("GET"_method)(
      [this](const crow::request&, int iIdpId) -> crow::response {
        try {
          auto oIdp = _irRepo.findById(iIdpId);
          if (!oIdp.has_value() || !oIdp->bIsEnabled || oIdp->sType != "saml") {
            throw common::NotFoundError("IDP_NOT_FOUND", "SAML identity provider not found");
          }

          std::string sSpEntityId = oIdp->jConfig.value("entity_id", "");
          std::string sSsoUrl = oIdp->jConfig.value("sso_url", "");
          std::string sAcsUrl = oIdp->jConfig.value("assertion_consumer_service_url", "");

          // Generate AuthnRequest
          std::string sAuthnRequest = _ssService.generateAuthnRequest(
              sSpEntityId, sAcsUrl, sSsoUrl);

          // Extract request ID from the generated XML (between ID=" and ")
          std::string sRequestId;
          auto iIdStart = sAuthnRequest.find("ID=\"");
          if (iIdStart != std::string::npos) {
            iIdStart += 4;
            auto iIdEnd = sAuthnRequest.find('"', iIdStart);
            if (iIdEnd != std::string::npos) {
              sRequestId = sAuthnRequest.substr(iIdStart, iIdEnd - iIdStart);
            }
          }

          // Generate relay state and store SAML auth state
          auto sRelayState = dns::security::OidcService::generateState();
          dns::security::SamlAuthState saState;
          saState.iIdpId = iIdpId;
          saState.sRequestId = sRequestId;
          saState.bIsTestMode = false;
          saState.tpCreatedAt = std::chrono::system_clock::now();
          _ssService.storeAuthState(sRelayState, saState);

          // Build redirect URL
          std::string sUrl = _ssService.buildRedirectUrl(sSsoUrl, sAuthnRequest, sRelayState);

          // Return 302 redirect
          crow::response resp(302);
          resp.set_header("Location", sUrl);
          return resp;
        } catch (const common::AppError& e) {
          return errorResponse(e);
        }
      });

  // POST /api/v1/auth/saml/<int>/acs — Assertion Consumer Service
  CROW_ROUTE(app, "/api/v1/auth/saml/<int>/acs").methods("POST"_method)(
      [this](const crow::request& req, int iIdpId) -> crow::response {
        try {
          // Parse URL-encoded form body
          std::string sSamlResponse;
          std::string sRelayState;

          // Crow provides url_params for query strings; for POST body we parse manually
          std::string sBody = req.body;
          auto parseFormParam = [&sBody](const std::string& sKey) -> std::string {
            std::string sSearch = sKey + "=";
            auto iStart = sBody.find(sSearch);
            if (iStart == std::string::npos) return "";
            iStart += sSearch.size();
            auto iEnd = sBody.find('&', iStart);
            std::string sValue = (iEnd != std::string::npos)
                                     ? sBody.substr(iStart, iEnd - iStart)
                                     : sBody.substr(iStart);
            // URL-decode
            std::string sDecoded;
            for (size_t i = 0; i < sValue.size(); ++i) {
              if (sValue[i] == '%' && i + 2 < sValue.size()) {
                int iHigh = 0, iLow = 0;
                auto hexVal = [](char c) -> int {
                  if (c >= '0' && c <= '9') return c - '0';
                  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                  return 0;
                };
                iHigh = hexVal(sValue[i + 1]);
                iLow = hexVal(sValue[i + 2]);
                sDecoded += static_cast<char>((iHigh << 4) | iLow);
                i += 2;
              } else if (sValue[i] == '+') {
                sDecoded += ' ';
              } else {
                sDecoded += sValue[i];
              }
            }
            return sDecoded;
          };

          sSamlResponse = parseFormParam("SAMLResponse");
          sRelayState = parseFormParam("RelayState");

          if (sSamlResponse.empty()) {
            throw common::ValidationError("MISSING_SAML_RESPONSE",
                                          "Missing SAMLResponse parameter");
          }

          // Consume auth state via relay state
          std::optional<dns::security::SamlAuthState> oState;
          if (!sRelayState.empty()) {
            oState = _ssService.consumeAuthState(sRelayState);
          }
          if (!oState.has_value()) {
            throw common::AuthenticationError("INVALID_RELAY_STATE",
                                              "Invalid or expired relay state");
          }

          if (oState->iIdpId != iIdpId) {
            throw common::AuthenticationError("STATE_MISMATCH",
                                              "Relay state IdP ID does not match URL");
          }

          // Load IdP
          auto oIdp = _irRepo.findById(iIdpId);
          if (!oIdp.has_value()) {
            throw common::NotFoundError("IDP_NOT_FOUND", "Identity provider not found");
          }

          std::string sCertificate = oIdp->jConfig.value("certificate", "");
          std::string sSpEntityId = oIdp->jConfig.value("entity_id", "");
          std::string sGroupAttribute = oIdp->jConfig.value("group_attribute", "groups");

          // Validate assertion
          auto jResult = _ssService.validateAssertion(
              sSamlResponse, sCertificate, sSpEntityId, oState->sRequestId);

          std::string sNameId = jResult.value("name_id", "");
          auto& jAttributes = jResult["attributes"];

          // Extract groups
          std::vector<std::string> vGroups;
          if (jAttributes.contains(sGroupAttribute) &&
              jAttributes[sGroupAttribute].is_array()) {
            for (const auto& g : jAttributes[sGroupAttribute]) {
              vGroups.push_back(g.get<std::string>());
            }
          }

          // Extract email
          std::string sEmail;
          if (jAttributes.contains("email") && jAttributes["email"].is_array() &&
              !jAttributes["email"].empty()) {
            sEmail = jAttributes["email"][0].get<std::string>();
          }

          // Username from NameID or email
          std::string sUsername = sNameId;
          if (sUsername.empty()) sUsername = sEmail;

          // Test mode: return HTML page displaying raw attributes
          if (oState->bIsTestMode) {
            nlohmann::json jTestResult = {
                {"subject", sNameId},
                {"email", sEmail},
                {"username", sUsername},
                {"groups", vGroups},
                {"all_claims", jAttributes},
            };
            std::string sHtml =
                "<!DOCTYPE html><html><head><title>SAML Test Result</title></head>"
                "<body><h1>SAML Test Result</h1>"
                "<pre>" + jTestResult.dump(2) + "</pre>"
                "<script>if(window.opener){window.opener.postMessage(" +
                jTestResult.dump() + ",'*');}</script>"
                "</body></html>";
            crow::response resp(200);
            resp.set_header("Content-Type", "text/html");
            resp.body = sHtml;
            return resp;
          }

          // Process federated login
          auto lr = _fasService.processFederatedLogin(
              "saml", sNameId, sUsername, sEmail, vGroups,
              oIdp->jGroupMappings, oIdp->iDefaultGroupId);

          // Return HTML page with JavaScript redirect (SAML POST binding can't redirect directly)
          std::string sHtml =
              "<!DOCTYPE html><html><head><title>Signing in...</title></head>"
              "<body><p>Signing in...</p>"
              "<script>window.location.replace('/auth/callback?token=" +
              lr.sToken + "');</script>"
              "</body></html>";
          crow::response resp(200);
          resp.set_header("Content-Type", "text/html");
          resp.body = sHtml;
          return resp;
        } catch (const common::AppError& e) {
          spdlog::error("SAML ACS error: {}", e.what());
          // Return HTML error page
          std::string sHtml =
              "<!DOCTYPE html><html><head><title>Authentication Error</title></head>"
              "<body><p>Authentication failed.</p>"
              "<script>window.location.replace('/login?error=auth_failed');</script>"
              "</body></html>";
          crow::response resp(200);
          resp.set_header("Content-Type", "text/html");
          resp.body = sHtml;
          return resp;
        }
      });
}

}  // namespace dns::api::routes
