#pragma once

#include <memory>
#include <string>

#include "providers/IProvider.hpp"

namespace dns::providers {

/// Creates concrete IProvider instances by type string.
class ProviderFactory {
 public:
  static std::unique_ptr<IProvider> create(const std::string& sType,
                                           const std::string& sApiEndpoint,
                                           const std::string& sDecryptedToken);
};

}  // namespace dns::providers
