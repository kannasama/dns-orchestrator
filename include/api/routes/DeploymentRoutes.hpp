#pragma once

namespace dns::api::routes {

/// Handlers for /api/v1/zones/{id}/deployments and rollback
class DeploymentRoutes {
 public:
  DeploymentRoutes();
  ~DeploymentRoutes();

  void registerRoutes();
};

}  // namespace dns::api::routes
