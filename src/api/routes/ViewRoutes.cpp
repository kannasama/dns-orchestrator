#include "api/routes/ViewRoutes.hpp"

#include <stdexcept>

namespace dns::api::routes {

ViewRoutes::ViewRoutes() = default;
ViewRoutes::~ViewRoutes() = default;

void ViewRoutes::registerRoutes() { throw std::runtime_error{"not implemented"}; }

}  // namespace dns::api::routes
