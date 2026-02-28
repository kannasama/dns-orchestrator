#pragma once

namespace dns::api::routes {

/// Handlers for /api/v1/views
class ViewRoutes {
 public:
  ViewRoutes();
  ~ViewRoutes();

  void registerRoutes();
};

}  // namespace dns::api::routes
