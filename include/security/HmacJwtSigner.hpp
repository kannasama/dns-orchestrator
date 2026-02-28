#pragma once

#include <string>

#include "security/IJwtSigner.hpp"

namespace dns::security {

/// HS256 JWT signing implementation using OpenSSL HMAC.
class HmacJwtSigner : public IJwtSigner {
 public:
  explicit HmacJwtSigner(const std::string& sSecret);
  ~HmacJwtSigner() override;

  std::string sign(const nlohmann::json& jPayload) const override;
  nlohmann::json verify(const std::string& sToken) const override;

 private:
  std::string _sSecret;
};

}  // namespace dns::security
