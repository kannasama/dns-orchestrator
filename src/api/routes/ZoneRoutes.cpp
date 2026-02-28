#include "api/routes/ZoneRoutes.hpp"

#include <stdexcept>

namespace dns::api::routes {

ZoneRoutes::ZoneRoutes() = default;
ZoneRoutes::~ZoneRoutes() = default;

void ZoneRoutes::registerRoutes() { throw std::runtime_error{"not implemented"}; }

}  // namespace dns::api::routes
