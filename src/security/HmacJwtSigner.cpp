#include "security/HmacJwtSigner.hpp"

#include <stdexcept>

namespace dns::security {

HmacJwtSigner::HmacJwtSigner(const std::string& /*sSecret*/) {
  throw std::runtime_error{"not implemented"};
}

HmacJwtSigner::~HmacJwtSigner() = default;

std::string HmacJwtSigner::sign(const nlohmann::json& /*jPayload*/) const {
  throw std::runtime_error{"not implemented"};
}

nlohmann::json HmacJwtSigner::verify(const std::string& /*sToken*/) const {
  throw std::runtime_error{"not implemented"};
}

}  // namespace dns::security
