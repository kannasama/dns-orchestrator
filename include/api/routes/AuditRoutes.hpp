#pragma once

namespace dns::api::routes {

/// Handlers for /api/v1/audit
class AuditRoutes {
 public:
  AuditRoutes();
  ~AuditRoutes();

  void registerRoutes();
};

}  // namespace dns::api::routes
