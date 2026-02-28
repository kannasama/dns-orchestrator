#include "api/routes/HealthRoutes.hpp"

#include <stdexcept>

namespace dns::api::routes {

HealthRoutes::HealthRoutes() = default;
HealthRoutes::~HealthRoutes() = default;

void HealthRoutes::registerRoutes() { throw std::runtime_error{"not implemented"}; }

}  // namespace dns::api::routes
