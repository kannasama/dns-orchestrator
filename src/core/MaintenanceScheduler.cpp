#include "core/MaintenanceScheduler.hpp"

#include <stdexcept>

namespace dns::core {

MaintenanceScheduler::MaintenanceScheduler() = default;
MaintenanceScheduler::~MaintenanceScheduler() = default;

void MaintenanceScheduler::schedule(const std::string& /*sName*/,
                                    std::chrono::seconds /*durInterval*/,
                                    std::function<void()> /*fnTask*/) {
  throw std::runtime_error{"not implemented"};
}

void MaintenanceScheduler::start() { throw std::runtime_error{"not implemented"}; }
void MaintenanceScheduler::stop() { throw std::runtime_error{"not implemented"}; }

}  // namespace dns::core
