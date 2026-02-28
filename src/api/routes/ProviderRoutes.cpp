#include "api/routes/ProviderRoutes.hpp"

#include <stdexcept>

namespace dns::api::routes {

ProviderRoutes::ProviderRoutes() = default;
ProviderRoutes::~ProviderRoutes() = default;

void ProviderRoutes::registerRoutes() { throw std::runtime_error{"not implemented"}; }

}  // namespace dns::api::routes
