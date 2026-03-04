#pragma once

#include <crow.h>

namespace dns::dal {
class ProviderRepository;
}

namespace dns::api {
class AuthMiddleware;
}

namespace dns::api::routes {

/// Handlers for /api/v1/providers
/// Class abbreviation: pr
class ProviderRoutes {
 public:
  ProviderRoutes(dns::dal::ProviderRepository& prRepo,
                 const dns::api::AuthMiddleware& amMiddleware);
  ~ProviderRoutes();

  /// Register provider routes on the Crow app.
  void registerRoutes(crow::SimpleApp& app);

 private:
  dns::dal::ProviderRepository& _prRepo;
  const dns::api::AuthMiddleware& _amMiddleware;
};

}  // namespace dns::api::routes
