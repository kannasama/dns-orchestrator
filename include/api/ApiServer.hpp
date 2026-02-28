#pragma once

#include <memory>
#include <string>

namespace dns::api {

/// Owns the Crow application instance; registers all routes at startup.
/// Class abbreviation: api
class ApiServer {
 public:
  ApiServer();
  ~ApiServer();

  void registerRoutes();
  void start(int iPort, int iThreads);
  void stop();
};

}  // namespace dns::api
