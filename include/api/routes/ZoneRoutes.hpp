#pragma once

namespace dns::api::routes {

/// Handlers for /api/v1/zones
class ZoneRoutes {
 public:
  ZoneRoutes();
  ~ZoneRoutes();

  void registerRoutes();
};

}  // namespace dns::api::routes
