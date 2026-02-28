#pragma once

#include <string>

#include <nlohmann/json.hpp>

namespace dns::security {

/// Pure abstract interface for JWT signing and verification.
class IJwtSigner {
 public:
  virtual ~IJwtSigner() = default;

  virtual std::string sign(const nlohmann::json& jPayload) const = 0;
  virtual nlohmann::json verify(const std::string& sToken) const = 0;
};

}  // namespace dns::security
