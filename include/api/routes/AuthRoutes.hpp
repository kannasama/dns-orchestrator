#pragma once

namespace dns::api::routes {

/// Handlers for /api/v1/auth
class AuthRoutes {
 public:
  AuthRoutes();
  ~AuthRoutes();

  void registerRoutes();
};

}  // namespace dns::api::routes
