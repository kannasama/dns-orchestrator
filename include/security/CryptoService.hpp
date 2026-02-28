#pragma once

#include <string>

namespace dns::security {

/// Cryptographic operations: AES-256-GCM encryption and API key hashing.
/// Class abbreviation: cs
class CryptoService {
 public:
  explicit CryptoService(const std::string& sMasterKeyHex);
  ~CryptoService();

  std::string encrypt(const std::string& sPlaintext) const;
  std::string decrypt(const std::string& sCiphertext) const;

  static std::string generateApiKey();
  static std::string hashApiKey(const std::string& sRawKey);

 private:
  std::string _sMasterKey;  // raw 32 bytes (not hex)
};

}  // namespace dns::security
