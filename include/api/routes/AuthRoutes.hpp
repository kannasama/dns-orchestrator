#pragma once

#include <crow.h>

namespace dns::security {
class AuthService;
}

namespace dns::api {
class AuthMiddleware;
}

namespace dns::api::routes {

/// Handlers for /api/v1/auth
/// Class abbreviation: ar
class AuthRoutes {
 public:
  AuthRoutes(dns::security::AuthService& asService,
             const dns::api::AuthMiddleware& amMiddleware);
  ~AuthRoutes();

  /// Register auth routes on the Crow app.
  void registerRoutes(crow::SimpleApp& app);

 private:
  dns::security::AuthService& _asService;
  const dns::api::AuthMiddleware& _amMiddleware;
};

}  // namespace dns::api::routes
