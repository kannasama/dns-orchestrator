#pragma once

#include <crow.h>

namespace dns::dal {
class VariableRepository;
}

namespace dns::api {
class AuthMiddleware;
}

namespace dns::api::routes {

/// Handlers for /api/v1/variables
/// Class abbreviation: var
class VariableRoutes {
 public:
  VariableRoutes(dns::dal::VariableRepository& varRepo,
                 const dns::api::AuthMiddleware& amMiddleware);
  ~VariableRoutes();

  void registerRoutes(crow::SimpleApp& app);

 private:
  dns::dal::VariableRepository& _varRepo;
  const dns::api::AuthMiddleware& _amMiddleware;
};

}  // namespace dns::api::routes
