#include "api/AuthMiddleware.hpp"

#include <stdexcept>

namespace dns::api {

AuthMiddleware::AuthMiddleware() = default;
AuthMiddleware::~AuthMiddleware() = default;

common::RequestContext AuthMiddleware::authenticate(
    const std::string& /*sAuthHeader*/, const std::string& /*sApiKeyHeader*/) const {
  throw std::runtime_error{"not implemented"};
}

}  // namespace dns::api
