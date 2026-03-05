#pragma once

#include <crow.h>

namespace dns::dal {
class AuditRepository;
}

namespace dns::api {
class AuthMiddleware;
}

namespace dns::api::routes {

/// Handlers for /api/v1/audit
/// Class abbreviation: audr
class AuditRoutes {
 public:
  AuditRoutes(dns::dal::AuditRepository& arRepo,
              const dns::api::AuthMiddleware& amMiddleware,
              int iRetentionDays);
  ~AuditRoutes();

  void registerRoutes(crow::SimpleApp& app);

 private:
  dns::dal::AuditRepository& _arRepo;
  const dns::api::AuthMiddleware& _amMiddleware;
  int _iRetentionDays;
};

}  // namespace dns::api::routes
