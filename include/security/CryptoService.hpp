#pragma once

#include <string>
#include <vector>

namespace dns::security {

/// Cryptographic operations: AES-256-GCM encryption and API key hashing.
/// Master key is stored as raw 32 bytes (decoded from hex at construction).
/// Class abbreviation: cs
class CryptoService {
 public:
  /// Construct from a 64-character hex-encoded master key.
  /// The raw hex string is zeroed via OPENSSL_cleanse after decoding.
  explicit CryptoService(std::string sMasterKeyHex);
  ~CryptoService();

  CryptoService(const CryptoService&) = delete;
  CryptoService& operator=(const CryptoService&) = delete;

  /// Encrypt plaintext using AES-256-GCM with a per-operation 12-byte IV.
  /// Returns: base64(iv):base64(ciphertext + tag)
  std::string encrypt(const std::string& sPlaintext) const;

  /// Decrypt ciphertext in format: base64(iv):base64(ciphertext + tag)
  std::string decrypt(const std::string& sCiphertext) const;

  /// Generate a cryptographically random API key: 32 bytes → base64url (43 chars).
  static std::string generateApiKey();

  /// Hash a raw API key with SHA-512 → hex string (128 chars).
  static std::string hashApiKey(const std::string& sRawKey);

  /// SHA-256 hash → 64-char lowercase hex string.
  /// Used to hash JWTs for session table lookups.
  static std::string sha256Hex(const std::string& sInput);

  /// Hash a password with Argon2id → PHC-formatted string.
  /// Format: $argon2id$v=19$m=65536,t=3,p=1$<base64_salt>$<base64_hash>
  static std::string hashPassword(const std::string& sPassword);

  /// Verify a password against a PHC-formatted Argon2id hash.
  /// Returns true if the password matches, false otherwise.
  /// Uses constant-time comparison for the hash.
  static bool verifyPassword(const std::string& sPassword, const std::string& sHash);

 private:
  std::vector<unsigned char> _vMasterKey;  // raw 32 bytes

  static std::string base64Encode(const std::vector<unsigned char>& vData);
  static std::vector<unsigned char> base64Decode(const std::string& sEncoded);
  static std::string base64UrlEncode(const std::vector<unsigned char>& vData);
  static std::vector<unsigned char> hexDecode(const std::string& sHex);
};

}  // namespace dns::security
