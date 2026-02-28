#pragma once

namespace dns::dal {

/// Manages the deployments table; snapshot create, get, list, prune.
class DeploymentRepository {
 public:
  DeploymentRepository();
  ~DeploymentRepository();
};

}  // namespace dns::dal
