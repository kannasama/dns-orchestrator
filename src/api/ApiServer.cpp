#include "api/ApiServer.hpp"

#include "api/routes/AuthRoutes.hpp"
#include "api/routes/ProviderRoutes.hpp"
#include "api/routes/RecordRoutes.hpp"
#include "api/routes/VariableRoutes.hpp"
#include "api/routes/ViewRoutes.hpp"
#include "api/routes/ZoneRoutes.hpp"

namespace dns::api {

ApiServer::ApiServer(crow::SimpleApp& app,
                     routes::AuthRoutes& arRoutes,
                     routes::ProviderRoutes& prRoutes,
                     routes::ViewRoutes& vrRoutes,
                     routes::ZoneRoutes& zrRoutes,
                     routes::RecordRoutes& rrRoutes,
                     routes::VariableRoutes& varRoutes)
    : _app(app),
      _arRoutes(arRoutes),
      _prRoutes(prRoutes),
      _vrRoutes(vrRoutes),
      _zrRoutes(zrRoutes),
      _rrRoutes(rrRoutes),
      _varRoutes(varRoutes) {}

ApiServer::~ApiServer() = default;

void ApiServer::registerRoutes() {
  _arRoutes.registerRoutes(_app);
  _prRoutes.registerRoutes(_app);
  _vrRoutes.registerRoutes(_app);
  _zrRoutes.registerRoutes(_app);
  _rrRoutes.registerRoutes(_app);
  _varRoutes.registerRoutes(_app);
}

void ApiServer::start(int iPort, int iThreads) {
  _app.port(iPort).multithreaded().concurrency(iThreads).run();
}

void ApiServer::stop() {
  _app.stop();
}

}  // namespace dns::api
