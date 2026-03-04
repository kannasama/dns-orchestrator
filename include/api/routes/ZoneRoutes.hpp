#pragma once

#include <crow.h>

namespace dns::dal {
class ZoneRepository;
}

namespace dns::api {
class AuthMiddleware;
}

namespace dns::api::routes {

/// Handlers for /api/v1/zones
/// Class abbreviation: zr
class ZoneRoutes {
 public:
  ZoneRoutes(dns::dal::ZoneRepository& zrRepo,
             const dns::api::AuthMiddleware& amMiddleware);
  ~ZoneRoutes();

  void registerRoutes(crow::SimpleApp& app);

 private:
  dns::dal::ZoneRepository& _zrRepo;
  const dns::api::AuthMiddleware& _amMiddleware;
};

}  // namespace dns::api::routes
