#pragma once

#include <crow.h>

namespace dns::api {
class AuthMiddleware;
}

namespace dns::api::routes {
class AuthRoutes;
class ProviderRoutes;
class ViewRoutes;
class ZoneRoutes;
class RecordRoutes;
class VariableRoutes;
}  // namespace dns::api::routes

namespace dns::api {

/// Owns the Crow application instance; registers all routes at startup.
/// Class abbreviation: api
class ApiServer {
 public:
  ApiServer(crow::SimpleApp& app,
            routes::AuthRoutes& arRoutes,
            routes::ProviderRoutes& prRoutes,
            routes::ViewRoutes& vrRoutes,
            routes::ZoneRoutes& zrRoutes,
            routes::RecordRoutes& rrRoutes,
            routes::VariableRoutes& varRoutes);
  ~ApiServer();

  /// Register all route handlers on the Crow app.
  void registerRoutes();

  /// Start the HTTP server. Blocks on the Crow event loop.
  void start(int iPort, int iThreads);

  /// Stop the HTTP server.
  void stop();

 private:
  crow::SimpleApp& _app;
  routes::AuthRoutes& _arRoutes;
  routes::ProviderRoutes& _prRoutes;
  routes::ViewRoutes& _vrRoutes;
  routes::ZoneRoutes& _zrRoutes;
  routes::RecordRoutes& _rrRoutes;
  routes::VariableRoutes& _varRoutes;
};

}  // namespace dns::api
