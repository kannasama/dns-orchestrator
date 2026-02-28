#pragma once

namespace dns::api::routes {

/// Handler for /api/v1/health
class HealthRoutes {
 public:
  HealthRoutes();
  ~HealthRoutes();

  void registerRoutes();
};

}  // namespace dns::api::routes
