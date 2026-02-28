#include "providers/ProviderFactory.hpp"

#include <stdexcept>

namespace dns::providers {

std::unique_ptr<IProvider> ProviderFactory::create(const std::string& /*sType*/,
                                                   const std::string& /*sApiEndpoint*/,
                                                   const std::string& /*sDecryptedToken*/) {
  throw std::runtime_error{"not implemented"};
}

}  // namespace dns::providers
