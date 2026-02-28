#include "api/routes/VariableRoutes.hpp"

#include <stdexcept>

namespace dns::api::routes {

VariableRoutes::VariableRoutes() = default;
VariableRoutes::~VariableRoutes() = default;

void VariableRoutes::registerRoutes() { throw std::runtime_error{"not implemented"}; }

}  // namespace dns::api::routes
