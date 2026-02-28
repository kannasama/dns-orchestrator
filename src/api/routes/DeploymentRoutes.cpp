#include "api/routes/DeploymentRoutes.hpp"

#include <stdexcept>

namespace dns::api::routes {

DeploymentRoutes::DeploymentRoutes() = default;
DeploymentRoutes::~DeploymentRoutes() = default;

void DeploymentRoutes::registerRoutes() { throw std::runtime_error{"not implemented"}; }

}  // namespace dns::api::routes
