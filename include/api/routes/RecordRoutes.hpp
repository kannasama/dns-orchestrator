#pragma once

#include <crow.h>

namespace dns::dal {
class RecordRepository;
}

namespace dns::api {
class AuthMiddleware;
}

namespace dns::api::routes {

/// Handlers for /api/v1/zones/{id}/records
/// Class abbreviation: rr
class RecordRoutes {
 public:
  RecordRoutes(dns::dal::RecordRepository& rrRepo,
               const dns::api::AuthMiddleware& amMiddleware);
  ~RecordRoutes();

  void registerRoutes(crow::SimpleApp& app);

 private:
  dns::dal::RecordRepository& _rrRepo;
  const dns::api::AuthMiddleware& _amMiddleware;
};

}  // namespace dns::api::routes
