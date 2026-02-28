#include "core/DeploymentEngine.hpp"

#include <stdexcept>

namespace dns::core {

DeploymentEngine::DeploymentEngine() = default;
DeploymentEngine::~DeploymentEngine() = default;

void DeploymentEngine::push(int64_t /*iZoneId*/, bool /*bPurgeDrift*/,
                            const std::string& /*sActor*/) {
  throw std::runtime_error{"not implemented"};
}

}  // namespace dns::core
