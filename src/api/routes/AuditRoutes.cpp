#include "api/routes/AuditRoutes.hpp"

#include <stdexcept>

namespace dns::api::routes {

AuditRoutes::AuditRoutes() = default;
AuditRoutes::~AuditRoutes() = default;

void AuditRoutes::registerRoutes() { throw std::runtime_error{"not implemented"}; }

}  // namespace dns::api::routes
