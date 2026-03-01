#include "security/AuthService.hpp"

#include "common/Errors.hpp"
#include "dal/SessionRepository.hpp"
#include "dal/UserRepository.hpp"
#include "security/CryptoService.hpp"
#include "security/IJwtSigner.hpp"

#include <chrono>

#include <nlohmann/json.hpp>

namespace dns::security {

AuthService::AuthService(dal::UserRepository& urRepo,
                         dal::SessionRepository& srRepo,
                         const IJwtSigner& jsSigner,
                         int iJwtTtlSeconds,
                         int iSessionAbsoluteTtlSeconds)
    : _urRepo(urRepo),
      _srRepo(srRepo),
      _jsSigner(jsSigner),
      _iJwtTtlSeconds(iJwtTtlSeconds),
      _iSessionAbsoluteTtlSeconds(iSessionAbsoluteTtlSeconds) {}

AuthService::~AuthService() = default;

std::string AuthService::authenticateLocal(const std::string& sUsername,
                                           const std::string& sPassword) {
  // Look up user — use same error message for unknown user and wrong password
  // to prevent username enumeration
  auto oUser = _urRepo.findByUsername(sUsername);
  if (!oUser.has_value()) {
    throw common::AuthenticationError("invalid_credentials", "Invalid username or password");
  }

  if (!oUser->bIsActive) {
    throw common::AuthenticationError("account_disabled", "User account is disabled");
  }

  // Verify password
  if (!CryptoService::verifyPassword(sPassword, oUser->sPasswordHash)) {
    throw common::AuthenticationError("invalid_credentials", "Invalid username or password");
  }

  // Resolve role
  std::string sRole = _urRepo.getHighestRole(oUser->iId);
  if (sRole.empty()) {
    sRole = "viewer";  // default role if no group membership
  }

  // Build JWT payload
  auto iNow = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();

  nlohmann::json jPayload = {
      {"sub", std::to_string(oUser->iId)},
      {"username", oUser->sUsername},
      {"role", sRole},
      {"auth_method", "local"},
      {"iat", iNow},
      {"exp", iNow + _iJwtTtlSeconds},
  };

  std::string sToken = _jsSigner.sign(jPayload);

  // Create session: store SHA-256 hash of the token, not the raw token
  std::string sTokenHash = CryptoService::sha256Hex(sToken);
  _srRepo.create(oUser->iId, sTokenHash, _iJwtTtlSeconds, _iSessionAbsoluteTtlSeconds);

  return sToken;
}

common::RequestContext AuthService::validateToken(const std::string& sToken) const {
  // Verify JWT signature and expiry (throws AuthenticationError on failure)
  nlohmann::json jPayload = _jsSigner.verify(sToken);

  // Check session exists and is valid
  std::string sTokenHash = CryptoService::sha256Hex(sToken);
  if (!_srRepo.isValid(sTokenHash)) {
    // Clean up the expired/revoked session if it still exists
    if (_srRepo.exists(sTokenHash)) {
      _srRepo.deleteByHash(sTokenHash);
    }
    throw common::AuthenticationError("token_revoked", "Session has been revoked or expired");
  }

  // Touch session to extend sliding window
  _srRepo.touch(sTokenHash, _iJwtTtlSeconds, _iSessionAbsoluteTtlSeconds);

  // Build RequestContext from JWT payload
  common::RequestContext rcCtx;
  rcCtx.iUserId = std::stoll(jPayload["sub"].get<std::string>());
  rcCtx.sUsername = jPayload["username"].get<std::string>();
  rcCtx.sRole = jPayload["role"].get<std::string>();
  rcCtx.sAuthMethod = jPayload["auth_method"].get<std::string>();

  return rcCtx;
}

}  // namespace dns::security
