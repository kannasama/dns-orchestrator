#include "api/routes/RecordRoutes.hpp"

#include <stdexcept>

namespace dns::api::routes {

RecordRoutes::RecordRoutes() = default;
RecordRoutes::~RecordRoutes() = default;

void RecordRoutes::registerRoutes() { throw std::runtime_error{"not implemented"}; }

}  // namespace dns::api::routes
