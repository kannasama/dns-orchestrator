#pragma once

#include <string>

#include "common/Types.hpp"

namespace dns::api {

/// JWT validation; injects RequestContext with identity.
class AuthMiddleware {
 public:
  AuthMiddleware();
  ~AuthMiddleware();

  common::RequestContext authenticate(const std::string& sAuthHeader,
                                      const std::string& sApiKeyHeader) const;
};

}  // namespace dns::api
