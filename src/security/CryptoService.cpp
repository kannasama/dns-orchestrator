#include "security/CryptoService.hpp"

#include "common/Errors.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

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

}  // namespace dns::security
