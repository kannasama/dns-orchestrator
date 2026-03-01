#include "security/CryptoService.hpp"

#include "common/Errors.hpp"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include <cstdio>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace dns::security {

namespace {
constexpr int kAesKeyLen = 32;     // AES-256
constexpr int kIvLen = 12;         // GCM standard IV
constexpr int kTagLen = 16;        // GCM tag
constexpr int kApiKeyBytes = 32;   // 32 random bytes → 43 base64url chars
}  // namespace

// ── Hex decode ─────────────────────────────────────────────────────────────

std::vector<unsigned char> CryptoService::hexDecode(const std::string& sHex) {
  if (sHex.size() % 2 != 0) {
    throw std::runtime_error("Invalid hex string: odd length");
  }
  std::vector<unsigned char> vResult;
  vResult.reserve(sHex.size() / 2);
  for (size_t i = 0; i < sHex.size(); i += 2) {
    unsigned int iByte = 0;
    std::istringstream iss(sHex.substr(i, 2));
    iss >> std::hex >> iByte;
    if (iss.fail()) {
      throw std::runtime_error("Invalid hex character at position " + std::to_string(i));
    }
    vResult.push_back(static_cast<unsigned char>(iByte));
  }
  return vResult;
}

// ── Base64 encode/decode ───────────────────────────────────────────────────

std::string CryptoService::base64Encode(const std::vector<unsigned char>& vData) {
  EVP_ENCODE_CTX* pCtx = EVP_ENCODE_CTX_new();
  if (!pCtx) {
    throw std::runtime_error("Failed to create EVP_ENCODE_CTX");
  }

  EVP_EncodeInit(pCtx);

  // Output buffer: 4/3 * input + padding + newlines + null
  const int iMaxOut = static_cast<int>(vData.size()) * 2 + 64;
  std::vector<unsigned char> vOut(static_cast<size_t>(iMaxOut));
  int iOutLen = 0;
  int iTotalLen = 0;

  EVP_EncodeUpdate(pCtx, vOut.data(), &iOutLen,
                   vData.data(), static_cast<int>(vData.size()));
  iTotalLen += iOutLen;

  EVP_EncodeFinal(pCtx, vOut.data() + iTotalLen, &iOutLen);
  iTotalLen += iOutLen;

  EVP_ENCODE_CTX_free(pCtx);

  std::string sResult(reinterpret_cast<char*>(vOut.data()), static_cast<size_t>(iTotalLen));
  // Remove newlines that EVP_Encode adds
  std::erase(sResult, '\n');
  // Remove trailing padding newline
  while (!sResult.empty() && sResult.back() == '\n') {
    sResult.pop_back();
  }
  return sResult;
}

std::vector<unsigned char> CryptoService::base64Decode(const std::string& sEncoded) {
  EVP_ENCODE_CTX* pCtx = EVP_ENCODE_CTX_new();
  if (!pCtx) {
    throw std::runtime_error("Failed to create EVP_ENCODE_CTX");
  }

  EVP_DecodeInit(pCtx);

  std::vector<unsigned char> vOut(sEncoded.size());
  int iOutLen = 0;
  int iTotalLen = 0;

  int iRet = EVP_DecodeUpdate(pCtx, vOut.data(), &iOutLen,
                              reinterpret_cast<const unsigned char*>(sEncoded.data()),
                              static_cast<int>(sEncoded.size()));
  if (iRet < 0) {
    EVP_ENCODE_CTX_free(pCtx);
    throw std::runtime_error("Base64 decode failed");
  }
  iTotalLen += iOutLen;

  iRet = EVP_DecodeFinal(pCtx, vOut.data() + iTotalLen, &iOutLen);
  iTotalLen += iOutLen;

  EVP_ENCODE_CTX_free(pCtx);

  vOut.resize(static_cast<size_t>(iTotalLen));
  return vOut;
}

std::string CryptoService::base64UrlEncode(const std::vector<unsigned char>& vData) {
  std::string sB64 = base64Encode(vData);
  // Convert to base64url: + → -, / → _, remove trailing =
  for (auto& c : sB64) {
    if (c == '+') c = '-';
    else if (c == '/') c = '_';
  }
  while (!sB64.empty() && sB64.back() == '=') {
    sB64.pop_back();
  }
  return sB64;
}

// ── Constructor / Destructor ───────────────────────────────────────────────

CryptoService::CryptoService(std::string sMasterKeyHex) {
  if (sMasterKeyHex.size() != static_cast<size_t>(kAesKeyLen * 2)) {
    throw std::runtime_error(
        "DNS_MASTER_KEY must be a 64-character hex string (32 bytes), got " +
        std::to_string(sMasterKeyHex.size()) + " characters");
  }

  _vMasterKey = hexDecode(sMasterKeyHex);

  // Zero the raw hex string from memory (SEC-02)
  OPENSSL_cleanse(sMasterKeyHex.data(), sMasterKeyHex.size());
}

CryptoService::~CryptoService() {
  // Zero the master key from memory
  if (!_vMasterKey.empty()) {
    OPENSSL_cleanse(_vMasterKey.data(), _vMasterKey.size());
  }
}

// ── Encrypt ────────────────────────────────────────────────────────────────

std::string CryptoService::encrypt(const std::string& sPlaintext) const {
  // Generate random 12-byte IV
  std::vector<unsigned char> vIv(kIvLen);
  if (RAND_bytes(vIv.data(), kIvLen) != 1) {
    throw std::runtime_error("Failed to generate random IV");
  }

  // Create cipher context
  EVP_CIPHER_CTX* pCtx = EVP_CIPHER_CTX_new();
  if (!pCtx) {
    throw std::runtime_error("Failed to create cipher context");
  }

  // Initialize encryption
  if (EVP_EncryptInit_ex(pCtx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
    EVP_CIPHER_CTX_free(pCtx);
    throw std::runtime_error("Failed to initialize AES-256-GCM encryption");
  }

  // Set IV length
  if (EVP_CIPHER_CTX_ctrl(pCtx, EVP_CTRL_GCM_SET_IVLEN, kIvLen, nullptr) != 1) {
    EVP_CIPHER_CTX_free(pCtx);
    throw std::runtime_error("Failed to set IV length");
  }

  // Set key and IV
  if (EVP_EncryptInit_ex(pCtx, nullptr, nullptr, _vMasterKey.data(), vIv.data()) != 1) {
    EVP_CIPHER_CTX_free(pCtx);
    throw std::runtime_error("Failed to set encryption key/IV");
  }

  // Encrypt
  std::vector<unsigned char> vCiphertext(sPlaintext.size() + static_cast<size_t>(kTagLen));
  int iOutLen = 0;
  if (EVP_EncryptUpdate(pCtx, vCiphertext.data(), &iOutLen,
                        reinterpret_cast<const unsigned char*>(sPlaintext.data()),
                        static_cast<int>(sPlaintext.size())) != 1) {
    EVP_CIPHER_CTX_free(pCtx);
    throw std::runtime_error("Encryption failed");
  }
  int iCiphertextLen = iOutLen;

  // Finalize
  if (EVP_EncryptFinal_ex(pCtx, vCiphertext.data() + iCiphertextLen, &iOutLen) != 1) {
    EVP_CIPHER_CTX_free(pCtx);
    throw std::runtime_error("Encryption finalization failed");
  }
  iCiphertextLen += iOutLen;

  // Get GCM tag
  std::vector<unsigned char> vTag(kTagLen);
  if (EVP_CIPHER_CTX_ctrl(pCtx, EVP_CTRL_GCM_GET_TAG, kTagLen, vTag.data()) != 1) {
    EVP_CIPHER_CTX_free(pCtx);
    throw std::runtime_error("Failed to get GCM tag");
  }

  EVP_CIPHER_CTX_free(pCtx);

  // Combine ciphertext + tag
  vCiphertext.resize(static_cast<size_t>(iCiphertextLen));
  vCiphertext.insert(vCiphertext.end(), vTag.begin(), vTag.end());

  // Format: base64(iv):base64(ciphertext + tag)
  return base64Encode(vIv) + ":" + base64Encode(vCiphertext);
}

// ── Decrypt ────────────────────────────────────────────────────────────────

std::string CryptoService::decrypt(const std::string& sCiphertext) const {
  // Split on ':'
  const auto nSep = sCiphertext.find(':');
  if (nSep == std::string::npos) {
    throw common::ValidationError("invalid_ciphertext", "Ciphertext missing IV:data separator");
  }

  const auto vIv = base64Decode(sCiphertext.substr(0, nSep));
  const auto vData = base64Decode(sCiphertext.substr(nSep + 1));

  if (vIv.size() != kIvLen) {
    throw common::ValidationError("invalid_ciphertext", "Invalid IV length");
  }
  if (vData.size() < static_cast<size_t>(kTagLen)) {
    throw common::ValidationError("invalid_ciphertext", "Ciphertext too short for GCM tag");
  }

  // Split data into ciphertext and tag
  const size_t nCiphertextLen = vData.size() - static_cast<size_t>(kTagLen);
  const auto* pCiphertext = vData.data();
  const auto* pTag = vData.data() + nCiphertextLen;

  // Create cipher context
  EVP_CIPHER_CTX* pCtx = EVP_CIPHER_CTX_new();
  if (!pCtx) {
    throw std::runtime_error("Failed to create cipher context");
  }

  // Initialize decryption
  if (EVP_DecryptInit_ex(pCtx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
    EVP_CIPHER_CTX_free(pCtx);
    throw std::runtime_error("Failed to initialize AES-256-GCM decryption");
  }

  if (EVP_CIPHER_CTX_ctrl(pCtx, EVP_CTRL_GCM_SET_IVLEN, kIvLen, nullptr) != 1) {
    EVP_CIPHER_CTX_free(pCtx);
    throw std::runtime_error("Failed to set IV length");
  }

  if (EVP_DecryptInit_ex(pCtx, nullptr, nullptr, _vMasterKey.data(), vIv.data()) != 1) {
    EVP_CIPHER_CTX_free(pCtx);
    throw std::runtime_error("Failed to set decryption key/IV");
  }

  // Decrypt
  std::vector<unsigned char> vPlaintext(nCiphertextLen);
  int iOutLen = 0;
  if (EVP_DecryptUpdate(pCtx, vPlaintext.data(), &iOutLen,
                        pCiphertext, static_cast<int>(nCiphertextLen)) != 1) {
    EVP_CIPHER_CTX_free(pCtx);
    throw std::runtime_error("Decryption failed");
  }
  int iPlaintextLen = iOutLen;

  // Set GCM tag
  if (EVP_CIPHER_CTX_ctrl(pCtx, EVP_CTRL_GCM_SET_TAG, kTagLen,
                           const_cast<unsigned char*>(pTag)) != 1) {
    EVP_CIPHER_CTX_free(pCtx);
    throw std::runtime_error("Failed to set GCM tag for verification");
  }

  // Finalize — verifies tag
  if (EVP_DecryptFinal_ex(pCtx, vPlaintext.data() + iPlaintextLen, &iOutLen) != 1) {
    EVP_CIPHER_CTX_free(pCtx);
    throw common::AuthenticationError("decryption_failed",
                                       "GCM tag verification failed (data tampered or wrong key)");
  }
  iPlaintextLen += iOutLen;

  EVP_CIPHER_CTX_free(pCtx);

  return std::string(reinterpret_cast<char*>(vPlaintext.data()),
                     static_cast<size_t>(iPlaintextLen));
}

// ── API Key Generation ─────────────────────────────────────────────────────

std::string CryptoService::generateApiKey() {
  std::vector<unsigned char> vBytes(kApiKeyBytes);
  if (RAND_bytes(vBytes.data(), kApiKeyBytes) != 1) {
    throw std::runtime_error("Failed to generate random bytes for API key");
  }
  return base64UrlEncode(vBytes);
}

// ── API Key Hashing ────────────────────────────────────────────────────────

std::string CryptoService::hashApiKey(const std::string& sRawKey) {
  unsigned char vHash[EVP_MAX_MD_SIZE];
  unsigned int uHashLen = 0;

  EVP_MD_CTX* pCtx = EVP_MD_CTX_new();
  if (!pCtx) {
    throw std::runtime_error("Failed to create digest context");
  }

  if (EVP_DigestInit_ex(pCtx, EVP_sha512(), nullptr) != 1 ||
      EVP_DigestUpdate(pCtx, sRawKey.data(), sRawKey.size()) != 1 ||
      EVP_DigestFinal_ex(pCtx, vHash, &uHashLen) != 1) {
    EVP_MD_CTX_free(pCtx);
    throw std::runtime_error("SHA-512 hash computation failed");
  }

  EVP_MD_CTX_free(pCtx);

  // Convert to hex string (128 chars for SHA-512)
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (unsigned int i = 0; i < uHashLen; ++i) {
    oss << std::setw(2) << static_cast<int>(vHash[i]);
  }
  return oss.str();
}

// ── SHA-256 ────────────────────────────────────────────────────────────────

std::string CryptoService::sha256Hex(const std::string& sInput) {
  unsigned char vHash[EVP_MAX_MD_SIZE];
  unsigned int uHashLen = 0;

  EVP_MD_CTX* pCtx = EVP_MD_CTX_new();
  if (!pCtx) {
    throw std::runtime_error("Failed to create digest context");
  }

  if (EVP_DigestInit_ex(pCtx, EVP_sha256(), nullptr) != 1 ||
      EVP_DigestUpdate(pCtx, sInput.data(), sInput.size()) != 1 ||
      EVP_DigestFinal_ex(pCtx, vHash, &uHashLen) != 1) {
    EVP_MD_CTX_free(pCtx);
    throw std::runtime_error("SHA-256 hash computation failed");
  }

  EVP_MD_CTX_free(pCtx);

  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (unsigned int i = 0; i < uHashLen; ++i) {
    oss << std::setw(2) << static_cast<int>(vHash[i]);
  }
  return oss.str();
}

// ── Argon2id password hashing ──────────────────────────────────────────────

namespace {
constexpr uint32_t kArgon2MemoryCost = 65536;  // 64 MiB
constexpr uint32_t kArgon2TimeCost = 3;         // 3 iterations
constexpr uint32_t kArgon2Parallelism = 1;      // 1 lane
constexpr int kArgon2SaltLen = 16;              // 16 bytes
constexpr int kArgon2HashLen = 32;              // 32 bytes
}  // namespace

std::string CryptoService::hashPassword(const std::string& sPassword) {
  // Generate random salt
  std::vector<unsigned char> vSalt(kArgon2SaltLen);
  if (RAND_bytes(vSalt.data(), kArgon2SaltLen) != 1) {
    throw std::runtime_error("Failed to generate random salt");
  }

  // Derive hash using EVP_KDF Argon2id
  EVP_KDF* pKdf = EVP_KDF_fetch(nullptr, "ARGON2ID", nullptr);
  if (!pKdf) {
    throw std::runtime_error("Failed to fetch ARGON2ID KDF (requires OpenSSL >= 3.2)");
  }

  EVP_KDF_CTX* pCtx = EVP_KDF_CTX_new(pKdf);
  EVP_KDF_free(pKdf);
  if (!pCtx) {
    throw std::runtime_error("Failed to create KDF context");
  }

  std::vector<unsigned char> vHash(kArgon2HashLen);

  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_octet_string(
          OSSL_KDF_PARAM_PASSWORD,
          const_cast<char*>(sPassword.data()),
          sPassword.size()),
      OSSL_PARAM_construct_octet_string(
          OSSL_KDF_PARAM_SALT,
          vSalt.data(),
          vSalt.size()),
      OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, const_cast<uint32_t*>(&kArgon2TimeCost)),
      OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, const_cast<uint32_t*>(&kArgon2MemoryCost)),
      OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS, const_cast<uint32_t*>(&kArgon2Parallelism)),
      OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, const_cast<uint32_t*>(&kArgon2Parallelism)),
      OSSL_PARAM_construct_end(),
  };

  if (EVP_KDF_derive(pCtx, vHash.data(), vHash.size(), params) != 1) {
    EVP_KDF_CTX_free(pCtx);
    throw std::runtime_error("Argon2id key derivation failed");
  }

  EVP_KDF_CTX_free(pCtx);

  // Encode salt and hash as base64 (no padding, no newlines)
  std::string sSaltB64 = base64UrlEncode(vSalt);
  std::string sHashB64 = base64UrlEncode(vHash);

  // Format as PHC string
  return "$argon2id$v=19$m=" + std::to_string(kArgon2MemoryCost) +
         ",t=" + std::to_string(kArgon2TimeCost) +
         ",p=" + std::to_string(kArgon2Parallelism) +
         "$" + sSaltB64 + "$" + sHashB64;
}

bool CryptoService::verifyPassword(const std::string& sPassword, const std::string& sHash) {
  // Parse PHC string: $argon2id$v=19$m=65536,t=3,p=1$<salt>$<hash>
  // Split on '$' — fields: [0]="" [1]="argon2id" [2]="v=19" [3]="m=...,t=...,p=..." [4]=salt [5]=hash
  std::vector<std::string> vParts;
  std::istringstream iss(sHash);
  std::string sPart;
  while (std::getline(iss, sPart, '$')) {
    vParts.push_back(sPart);
  }

  if (vParts.size() != 6 || vParts[1] != "argon2id") {
    return false;
  }

  // Parse parameters from vParts[3]: "m=65536,t=3,p=1"
  uint32_t uMemory = 0, uTime = 0, uParallelism = 0;
  if (std::sscanf(vParts[3].c_str(), "m=%u,t=%u,p=%u", &uMemory, &uTime, &uParallelism) != 3) {
    return false;
  }

  // Decode salt from base64url
  // Re-add padding for base64 decode
  std::string sSaltB64 = vParts[4];
  for (auto& c : sSaltB64) {
    if (c == '-') c = '+';
    else if (c == '_') c = '/';
  }
  while (sSaltB64.size() % 4 != 0) sSaltB64 += '=';
  auto vSalt = base64Decode(sSaltB64);

  // Decode stored hash from base64url
  std::string sStoredB64 = vParts[5];
  for (auto& c : sStoredB64) {
    if (c == '-') c = '+';
    else if (c == '_') c = '/';
  }
  while (sStoredB64.size() % 4 != 0) sStoredB64 += '=';
  auto vStoredHash = base64Decode(sStoredB64);

  // Re-derive hash with parsed params and extracted salt
  EVP_KDF* pKdf = EVP_KDF_fetch(nullptr, "ARGON2ID", nullptr);
  if (!pKdf) return false;

  EVP_KDF_CTX* pCtx = EVP_KDF_CTX_new(pKdf);
  EVP_KDF_free(pKdf);
  if (!pCtx) return false;

  std::vector<unsigned char> vDerived(vStoredHash.size());

  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_octet_string(
          OSSL_KDF_PARAM_PASSWORD,
          const_cast<char*>(sPassword.data()),
          sPassword.size()),
      OSSL_PARAM_construct_octet_string(
          OSSL_KDF_PARAM_SALT,
          vSalt.data(),
          vSalt.size()),
      OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &uTime),
      OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &uMemory),
      OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS, &uParallelism),
      OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &uParallelism),
      OSSL_PARAM_construct_end(),
  };

  if (EVP_KDF_derive(pCtx, vDerived.data(), vDerived.size(), params) != 1) {
    EVP_KDF_CTX_free(pCtx);
    return false;
  }

  EVP_KDF_CTX_free(pCtx);

  // Constant-time comparison
  return CRYPTO_memcmp(vDerived.data(), vStoredHash.data(), vStoredHash.size()) == 0;
}

}  // namespace dns::security
