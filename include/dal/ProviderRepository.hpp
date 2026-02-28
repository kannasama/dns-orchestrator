#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace dns::dal {

/// Manages the providers table; decrypts tokens on read.
class ProviderRepository {
 public:
  ProviderRepository();
  ~ProviderRepository();
};

}  // namespace dns::dal
