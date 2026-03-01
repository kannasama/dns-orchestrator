#include "api/AuthMiddleware.hpp"

#include "common/Errors.hpp"
#include "dal/ApiKeyRepository.hpp"
#include "dal/SessionRepository.hpp"
#include "dal/UserRepository.hpp"
#include "security/CryptoService.hpp"
#include "security/IJwtSigner.hpp"

#include <nlohmann/json.hpp>

namespace dns::api {

AuthMiddleware::AuthMiddleware(const dns::security::IJwtSigner& jsSigner,
                               dns::dal::SessionRepository& srRepo,
                               dns::dal::ApiKeyRepository& akrRepo,
                               dns::dal::UserRepository& urRepo,
                               int iJwtTtlSeconds,
                               int iApiKeyCleanupGraceSeconds)
    : _jsSigner(jsSigner),
      _srRepo(srRepo),
      _akrRepo(akrRepo),
      _urRepo(urRepo),
      _iJwtTtlSeconds(iJwtTtlSeconds),
      _iApiKeyCleanupGraceSeconds(iApiKeyCleanupGraceSeconds) {}

AuthMiddleware::~AuthMiddleware() = default;

common::RequestContext AuthMiddleware::authenticate(
    const std::string& sAuthHeader,
    const std::string& sApiKeyHeader) const {
  // Check for Bearer token
  const std::string kBearerPrefix = "Bearer ";
  if (sAuthHeader.size() > kBearerPrefix.size() &&
      sAuthHeader.substr(0, kBearerPrefix.size()) == kBearerPrefix) {
    std::string sBearerToken = sAuthHeader.substr(kBearerPrefix.size());
    return validateJwt(sBearerToken);
  }

  // Check for API key
  if (!sApiKeyHeader.empty()) {
    return validateApiKey(sApiKeyHeader);
  }

  throw common::AuthenticationError("no_credentials", "No authentication credentials provided");
}

common::RequestContext AuthMiddleware::validateJwt(const std::string& sBearerToken) const {
  // Verify JWT signature and expiry (throws AuthenticationError on failure)
  nlohmann::json jPayload = _jsSigner.verify(sBearerToken);

  // Check session in DB
  std::string sTokenHash = dns::security::CryptoService::sha256Hex(sBearerToken);

  if (!_srRepo.exists(sTokenHash)) {
    throw common::AuthenticationError("token_revoked",
                                       "Session has been revoked or deleted");
  }

  if (!_srRepo.isValid(sTokenHash)) {
    _srRepo.deleteByHash(sTokenHash);
    throw common::AuthenticationError("token_expired",
                                       "Session has expired");
  }

  // Touch session to extend sliding window
  _srRepo.touch(sTokenHash, _iJwtTtlSeconds, 0);

  // Build RequestContext from JWT payload
  common::RequestContext rcCtx;
  rcCtx.iUserId = std::stoll(jPayload["sub"].get<std::string>());
  rcCtx.sUsername = jPayload["username"].get<std::string>();
  rcCtx.sRole = jPayload["role"].get<std::string>();
  rcCtx.sAuthMethod = jPayload["auth_method"].get<std::string>();

  return rcCtx;
}

common::RequestContext AuthMiddleware::validateApiKey(const std::string& sRawKey) const {
  // Hash the raw key with SHA-512 (matches storage format)
  std::string sKeyHash = dns::security::CryptoService::hashApiKey(sRawKey);

  auto oKey = _akrRepo.findByHash(sKeyHash);
  if (!oKey.has_value()) {
    throw common::AuthenticationError("invalid_api_key", "API key not found");
  }

  if (oKey->bRevoked) {
    throw common::AuthenticationError("api_key_revoked", "API key has been revoked");
  }

  // Check expiry
  if (oKey->oExpiresAt.has_value()) {
    auto tpNow = std::chrono::system_clock::now();
    if (tpNow > *oKey->oExpiresAt) {
      _akrRepo.scheduleDelete(oKey->iId, _iApiKeyCleanupGraceSeconds);
      throw common::AuthenticationError("api_key_expired", "API key has expired");
    }
  }

  // Look up user for identity context
  auto oUser = _urRepo.findById(oKey->iUserId);
  if (!oUser.has_value() || !oUser->bIsActive) {
    throw common::AuthenticationError("user_not_found",
                                       "API key owner not found or inactive");
  }

  // Resolve role
  std::string sRole = _urRepo.getHighestRole(oUser->iId);
  if (sRole.empty()) {
    sRole = "viewer";
  }

  common::RequestContext rcCtx;
  rcCtx.iUserId = oUser->iId;
  rcCtx.sUsername = oUser->sUsername;
  rcCtx.sRole = sRole;
  rcCtx.sAuthMethod = "api_key";

  return rcCtx;
}

}  // namespace dns::api
