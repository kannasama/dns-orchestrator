#include "security/CryptoService.hpp"

#include <stdexcept>

namespace dns::security {

CryptoService::CryptoService(const std::string& /*sMasterKeyHex*/) {
  throw std::runtime_error{"not implemented"};
}

CryptoService::~CryptoService() = default;

std::string CryptoService::encrypt(const std::string& /*sPlaintext*/) const {
  throw std::runtime_error{"not implemented"};
}

std::string CryptoService::decrypt(const std::string& /*sCiphertext*/) const {
  throw std::runtime_error{"not implemented"};
}

std::string CryptoService::generateApiKey() { throw std::runtime_error{"not implemented"}; }

std::string CryptoService::hashApiKey(const std::string& /*sRawKey*/) {
  throw std::runtime_error{"not implemented"};
}

}  // namespace dns::security
