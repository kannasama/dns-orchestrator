#pragma once

#include <crow.h>

namespace dns::dal {
class DeploymentRepository;
class RecordRepository;
}  // namespace dns::dal

namespace dns::core {
class RollbackEngine;
}

namespace dns::api {
class AuthMiddleware;
}

namespace dns::api::routes {

/// Handlers for /api/v1/zones/{id}/deployments and rollback
/// Class abbreviation: dplr
class DeploymentRoutes {
 public:
  DeploymentRoutes(dns::dal::DeploymentRepository& drRepo,
                   dns::dal::RecordRepository& rrRepo,
                   const dns::api::AuthMiddleware& amMiddleware,
                   dns::core::RollbackEngine& reEngine);
  ~DeploymentRoutes();

  void registerRoutes(crow::SimpleApp& app);

 private:
  dns::dal::DeploymentRepository& _drRepo;
  dns::dal::RecordRepository& _rrRepo;
  const dns::api::AuthMiddleware& _amMiddleware;
  dns::core::RollbackEngine& _reEngine;
};

}  // namespace dns::api::routes
