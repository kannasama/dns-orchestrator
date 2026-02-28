#pragma once

#include <string>

#include "common/Types.hpp"

namespace dns::security {

/// Handles local, OIDC, SAML, and API key authentication.
/// Class abbreviation: as
class AuthService {
 public:
  AuthService();
  ~AuthService();

  std::string authenticateLocal(const std::string& sUsername, const std::string& sPassword);
  common::RequestContext validateToken(const std::string& sToken) const;
};

}  // namespace dns::security
