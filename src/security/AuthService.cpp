#include "security/AuthService.hpp"

#include <stdexcept>

namespace dns::security {

AuthService::AuthService() = default;
AuthService::~AuthService() = default;

std::string AuthService::authenticateLocal(const std::string& /*sUsername*/,
                                           const std::string& /*sPassword*/) {
  throw std::runtime_error{"not implemented"};
}

common::RequestContext AuthService::validateToken(const std::string& /*sToken*/) const {
  throw std::runtime_error{"not implemented"};
}

}  // namespace dns::security
