#include "core/RollbackEngine.hpp"

#include <stdexcept>

namespace dns::core {

RollbackEngine::RollbackEngine() = default;
RollbackEngine::~RollbackEngine() = default;

void RollbackEngine::apply(int64_t /*iZoneId*/, int64_t /*iDeploymentId*/,
                           const std::vector<int64_t>& /*vCherryPickIds*/,
                           const std::string& /*sActor*/) {
  throw std::runtime_error{"not implemented"};
}

}  // namespace dns::core
