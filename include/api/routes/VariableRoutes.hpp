#pragma once

namespace dns::api::routes {

/// Handlers for /api/v1/variables
class VariableRoutes {
 public:
  VariableRoutes();
  ~VariableRoutes();

  void registerRoutes();
};

}  // namespace dns::api::routes
