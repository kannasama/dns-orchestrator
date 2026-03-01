#pragma once

#include <string>

#include "common/Types.hpp"

namespace dns::dal {
class UserRepository;
class SessionRepository;
class ApiKeyRepository;
}  // namespace dns::dal

namespace dns::security {
class IJwtSigner;
}

namespace dns::api {

/// JWT + API key validation; injects RequestContext with identity.
/// Class abbreviation: am
class AuthMiddleware {
 public:
  AuthMiddleware(const dns::security::IJwtSigner& jsSigner,
                 dns::dal::SessionRepository& srRepo,
                 dns::dal::ApiKeyRepository& akrRepo,
                 dns::dal::UserRepository& urRepo,
                 int iJwtTtlSeconds,
                 int iApiKeyCleanupGraceSeconds);
  ~AuthMiddleware();

  /// Authenticate a request using either Bearer JWT or X-API-Key header.
  /// Exactly one of sAuthHeader or sApiKeyHeader must be non-empty.
  /// Throws AuthenticationError (401) on failure.
  common::RequestContext authenticate(const std::string& sAuthHeader,
                                      const std::string& sApiKeyHeader) const;

 private:
  /// Validate Bearer JWT path.
  common::RequestContext validateJwt(const std::string& sBearerToken) const;

  /// Validate API key path.
  common::RequestContext validateApiKey(const std::string& sRawKey) const;

  const dns::security::IJwtSigner& _jsSigner;
  dns::dal::SessionRepository& _srRepo;
  dns::dal::ApiKeyRepository& _akrRepo;
  dns::dal::UserRepository& _urRepo;
  int _iJwtTtlSeconds;
  int _iApiKeyCleanupGraceSeconds;
};

}  // namespace dns::api
