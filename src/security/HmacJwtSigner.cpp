#include "security/HmacJwtSigner.hpp"

#include "common/Errors.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <chrono>
#include <cstring>
#include <sstream>
#include <vector>

namespace dns::security {

namespace {

// ── Base64url encode/decode ────────────────────────────────────────────────

std::string base64UrlEncode(const std::string& sInput) {
  // Use OpenSSL EVP base64
  EVP_ENCODE_CTX* pCtx = EVP_ENCODE_CTX_new();
  EVP_EncodeInit(pCtx);

  const int iMaxOut = static_cast<int>(sInput.size()) * 2 + 64;
  std::vector<unsigned char> vOut(static_cast<size_t>(iMaxOut));
  int iOutLen = 0;
  int iTotalLen = 0;

  EVP_EncodeUpdate(pCtx, vOut.data(), &iOutLen,
                   reinterpret_cast<const unsigned char*>(sInput.data()),
                   static_cast<int>(sInput.size()));
  iTotalLen += iOutLen;
  EVP_EncodeFinal(pCtx, vOut.data() + iTotalLen, &iOutLen);
  iTotalLen += iOutLen;
  EVP_ENCODE_CTX_free(pCtx);

  std::string sB64(reinterpret_cast<char*>(vOut.data()), static_cast<size_t>(iTotalLen));
  // Remove newlines
  std::erase(sB64, '\n');
  // Convert to base64url
  for (auto& c : sB64) {
    if (c == '+') c = '-';
    else if (c == '/') c = '_';
  }
  // Remove padding
  while (!sB64.empty() && sB64.back() == '=') {
    sB64.pop_back();
  }
  return sB64;
}

std::string base64UrlDecode(const std::string& sInput) {
  // Convert from base64url to base64
  std::string sB64 = sInput;
  for (auto& c : sB64) {
    if (c == '-') c = '+';
    else if (c == '_') c = '/';
  }
  // Add padding
  while (sB64.size() % 4 != 0) {
    sB64 += '=';
  }

  EVP_ENCODE_CTX* pCtx = EVP_ENCODE_CTX_new();
  EVP_DecodeInit(pCtx);

  std::vector<unsigned char> vOut(sB64.size());
  int iOutLen = 0;
  int iTotalLen = 0;

  int iRet = EVP_DecodeUpdate(pCtx, vOut.data(), &iOutLen,
                              reinterpret_cast<const unsigned char*>(sB64.data()),
                              static_cast<int>(sB64.size()));
  if (iRet < 0) {
    EVP_ENCODE_CTX_free(pCtx);
    throw common::AuthenticationError("invalid_token", "Failed to decode JWT segment");
  }
  iTotalLen += iOutLen;
  EVP_DecodeFinal(pCtx, vOut.data() + iTotalLen, &iOutLen);
  iTotalLen += iOutLen;
  EVP_ENCODE_CTX_free(pCtx);

  return std::string(reinterpret_cast<char*>(vOut.data()), static_cast<size_t>(iTotalLen));
}

std::string hmacSha256(const std::string& sKey, const std::string& sData) {
  unsigned char vHash[EVP_MAX_MD_SIZE];
  unsigned int uHashLen = 0;

  unsigned char* pResult = HMAC(
      EVP_sha256(),
      sKey.data(), static_cast<int>(sKey.size()),
      reinterpret_cast<const unsigned char*>(sData.data()),
      sData.size(),
      vHash, &uHashLen);

  if (!pResult) {
    throw std::runtime_error("HMAC-SHA256 computation failed");
  }

  return std::string(reinterpret_cast<char*>(vHash), uHashLen);
}

}  // anonymous namespace

// ── HmacJwtSigner ──────────────────────────────────────────────────────────

HmacJwtSigner::HmacJwtSigner(const std::string& sSecret) : _sSecret(sSecret) {
  if (_sSecret.empty()) {
    throw std::runtime_error("JWT secret cannot be empty");
  }
}

HmacJwtSigner::~HmacJwtSigner() {
  // Zero the secret from memory
  if (!_sSecret.empty()) {
    OPENSSL_cleanse(_sSecret.data(), _sSecret.size());
  }
}

std::string HmacJwtSigner::sign(const nlohmann::json& jPayload) const {
  // Header: {"alg":"HS256","typ":"JWT"}
  const nlohmann::json jHeader = {{"alg", "HS256"}, {"typ", "JWT"}};

  const std::string sHeader = base64UrlEncode(jHeader.dump());
  const std::string sPayload = base64UrlEncode(jPayload.dump());
  const std::string sSigningInput = sHeader + "." + sPayload;

  const std::string sRawSig = hmacSha256(_sSecret, sSigningInput);

  // base64url encode the raw binary signature
  EVP_ENCODE_CTX* pCtx = EVP_ENCODE_CTX_new();
  EVP_EncodeInit(pCtx);
  const int iMaxOut = static_cast<int>(sRawSig.size()) * 2 + 64;
  std::vector<unsigned char> vOut(static_cast<size_t>(iMaxOut));
  int iOutLen = 0, iTotalLen = 0;
  EVP_EncodeUpdate(pCtx, vOut.data(), &iOutLen,
                   reinterpret_cast<const unsigned char*>(sRawSig.data()),
                   static_cast<int>(sRawSig.size()));
  iTotalLen += iOutLen;
  EVP_EncodeFinal(pCtx, vOut.data() + iTotalLen, &iOutLen);
  iTotalLen += iOutLen;
  EVP_ENCODE_CTX_free(pCtx);

  std::string sSignature(reinterpret_cast<char*>(vOut.data()), static_cast<size_t>(iTotalLen));
  std::erase(sSignature, '\n');
  for (auto& c : sSignature) {
    if (c == '+') c = '-';
    else if (c == '/') c = '_';
  }
  while (!sSignature.empty() && sSignature.back() == '=') {
    sSignature.pop_back();
  }

  return sSigningInput + "." + sSignature;
}

nlohmann::json HmacJwtSigner::verify(const std::string& sToken) const {
  // Split into 3 parts
  const auto nDot1 = sToken.find('.');
  if (nDot1 == std::string::npos) {
    throw common::AuthenticationError("invalid_token", "Malformed JWT: missing first dot");
  }
  const auto nDot2 = sToken.find('.', nDot1 + 1);
  if (nDot2 == std::string::npos) {
    throw common::AuthenticationError("invalid_token", "Malformed JWT: missing second dot");
  }
  if (sToken.find('.', nDot2 + 1) != std::string::npos) {
    throw common::AuthenticationError("invalid_token", "Malformed JWT: too many dots");
  }

  const std::string sSigningInput = sToken.substr(0, nDot2);
  const std::string sProvidedSig = sToken.substr(nDot2 + 1);

  // Recompute signature
  const std::string sRawExpectedSig = hmacSha256(_sSecret, sSigningInput);

  // base64url encode expected signature for comparison
  EVP_ENCODE_CTX* pCtx = EVP_ENCODE_CTX_new();
  EVP_EncodeInit(pCtx);
  const int iMaxOut = static_cast<int>(sRawExpectedSig.size()) * 2 + 64;
  std::vector<unsigned char> vOut(static_cast<size_t>(iMaxOut));
  int iOutLen = 0, iTotalLen = 0;
  EVP_EncodeUpdate(pCtx, vOut.data(), &iOutLen,
                   reinterpret_cast<const unsigned char*>(sRawExpectedSig.data()),
                   static_cast<int>(sRawExpectedSig.size()));
  iTotalLen += iOutLen;
  EVP_EncodeFinal(pCtx, vOut.data() + iTotalLen, &iOutLen);
  iTotalLen += iOutLen;
  EVP_ENCODE_CTX_free(pCtx);

  std::string sExpectedSig(reinterpret_cast<char*>(vOut.data()), static_cast<size_t>(iTotalLen));
  std::erase(sExpectedSig, '\n');
  for (auto& c : sExpectedSig) {
    if (c == '+') c = '-';
    else if (c == '/') c = '_';
  }
  while (!sExpectedSig.empty() && sExpectedSig.back() == '=') {
    sExpectedSig.pop_back();
  }

  // Constant-time comparison to prevent timing attacks
  if (sExpectedSig.size() != sProvidedSig.size() ||
      CRYPTO_memcmp(sExpectedSig.data(), sProvidedSig.data(), sExpectedSig.size()) != 0) {
    throw common::AuthenticationError("invalid_signature", "JWT signature verification failed");
  }

  // Decode payload
  const std::string sPayloadB64 = sToken.substr(nDot1 + 1, nDot2 - nDot1 - 1);
  const std::string sPayloadJson = base64UrlDecode(sPayloadB64);

  nlohmann::json jPayload;
  try {
    jPayload = nlohmann::json::parse(sPayloadJson);
  } catch (const nlohmann::json::exception&) {
    throw common::AuthenticationError("invalid_token", "JWT payload is not valid JSON");
  }

  // Check expiry
  if (jPayload.contains("exp")) {
    const auto iExp = jPayload["exp"].get<int64_t>();
    const auto iNow = std::chrono::duration_cast<std::chrono::seconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();
    if (iNow > iExp) {
      throw common::AuthenticationError("token_expired", "JWT has expired");
    }
  }

  return jPayload;
}

}  // namespace dns::security
