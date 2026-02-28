#include "api/ApiServer.hpp"

#include <stdexcept>

namespace dns::api {

ApiServer::ApiServer() = default;
ApiServer::~ApiServer() = default;

void ApiServer::registerRoutes() { throw std::runtime_error{"not implemented"}; }
void ApiServer::start(int /*iPort*/, int /*iThreads*/) {
  throw std::runtime_error{"not implemented"};
}
void ApiServer::stop() { throw std::runtime_error{"not implemented"}; }

}  // namespace dns::api
