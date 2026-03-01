#pragma once

#include <cstdint>
#include <string>

#include "common/Types.hpp"

namespace dns::dal {
class ConnectionPool;
class UserRepository;
class SessionRepository;
}  // namespace dns::dal

namespace dns::security {

class IJwtSigner;

/// Handles local authentication (Argon2id) and JWT session creation.
/// Class abbreviation: as
class AuthService {
 public:
  AuthService(dal::UserRepository& urRepo,
              dal::SessionRepository& srRepo,
              const IJwtSigner& jsSigner,
              int iJwtTtlSeconds,
              int iSessionAbsoluteTtlSeconds);
  ~AuthService();

  /// Authenticate with username/password. Returns a signed JWT on success.
  /// Throws AuthenticationError on invalid credentials.
  /// Throws AuthenticationError if user account is inactive.
  std::string authenticateLocal(const std::string& sUsername, const std::string& sPassword);

  /// Validate a JWT token. Returns the identity context on success.
  /// Throws AuthenticationError on invalid/expired token.
  common::RequestContext validateToken(const std::string& sToken) const;

 private:
  dal::UserRepository& _urRepo;
  dal::SessionRepository& _srRepo;
  const IJwtSigner& _jsSigner;
  int _iJwtTtlSeconds;
  int _iSessionAbsoluteTtlSeconds;
};

}  // namespace dns::security
