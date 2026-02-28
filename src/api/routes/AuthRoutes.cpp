#include "api/routes/AuthRoutes.hpp"

#include <stdexcept>

namespace dns::api::routes {

AuthRoutes::AuthRoutes() = default;
AuthRoutes::~AuthRoutes() = default;

void AuthRoutes::registerRoutes() { throw std::runtime_error{"not implemented"}; }

}  // namespace dns::api::routes
