#pragma once

namespace dns::api::routes {

/// Handlers for /api/v1/providers
class ProviderRoutes {
 public:
  ProviderRoutes();
  ~ProviderRoutes();

  void registerRoutes();
};

}  // namespace dns::api::routes
