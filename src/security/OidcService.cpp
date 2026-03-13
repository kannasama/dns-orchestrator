#include "security/OidcService.hpp"

#include "common/Errors.hpp"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>

#include <httplib.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <cstring>
#include <sstream>
#include <vector>

namespace dns::security {

namespace {

// ── Base64url helpers (same pattern as HmacJwtSigner) ──────────────────────

std::string base64UrlEncode(const unsigned char* pData, size_t uLen) {
  EVP_ENCODE_CTX* pCtx = EVP_ENCODE_CTX_new();
  EVP_EncodeInit(pCtx);

  const int iMaxOut = static_cast<int>(uLen) * 2 + 64;
  std::vector<unsigned char> vOut(static_cast<size_t>(iMaxOut));
  int iOutLen = 0;
  int iTotalLen = 0;

  EVP_EncodeUpdate(pCtx, vOut.data(), &iOutLen, pData, static_cast<int>(uLen));
  iTotalLen += iOutLen;
  EVP_EncodeFinal(pCtx, vOut.data() + iTotalLen, &iOutLen);
  iTotalLen += iOutLen;
  EVP_ENCODE_CTX_free(pCtx);

  std::string sB64(reinterpret_cast<char*>(vOut.data()), static_cast<size_t>(iTotalLen));
  std::erase(sB64, '\n');
  for (auto& c : sB64) {
    if (c == '+') c = '-';
    else if (c == '/') c = '_';
  }
  while (!sB64.empty() && sB64.back() == '=') {
    sB64.pop_back();
  }
  return sB64;
}

std::string base64UrlDecode(const std::string& sInput) {
  std::string sB64 = sInput;
  for (auto& c : sB64) {
    if (c == '-') c = '+';
    else if (c == '_') c = '/';
  }
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
    throw common::AuthenticationError("invalid_token", "Failed to decode base64url segment");
  }
  iTotalLen += iOutLen;
  EVP_DecodeFinal(pCtx, vOut.data() + iTotalLen, &iOutLen);
  iTotalLen += iOutLen;
  EVP_ENCODE_CTX_free(pCtx);

  return std::string(reinterpret_cast<char*>(vOut.data()), static_cast<size_t>(iTotalLen));
}

std::vector<unsigned char> base64UrlDecodeBytes(const std::string& sInput) {
  std::string sDecoded = base64UrlDecode(sInput);
  return std::vector<unsigned char>(sDecoded.begin(), sDecoded.end());
}

std::string sha256Raw(const std::string& sInput) {
  unsigned char vHash[EVP_MAX_MD_SIZE];
  unsigned int uHashLen = 0;

  EVP_MD_CTX* pCtx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(pCtx, EVP_sha256(), nullptr);
  EVP_DigestUpdate(pCtx, sInput.data(), sInput.size());
  EVP_DigestFinal_ex(pCtx, vHash, &uHashLen);
  EVP_MD_CTX_free(pCtx);

  return std::string(reinterpret_cast<char*>(vHash), uHashLen);
}

std::string urlEncode(const std::string& sValue) {
  std::ostringstream oss;
  for (unsigned char c : sValue) {
    if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
      oss << c;
    } else {
      oss << '%' << std::uppercase << std::hex
          << static_cast<int>(c >> 4) << static_cast<int>(c & 0x0F);
    }
  }
  return oss.str();
}

/// Parse a URL into scheme+host and path components.
std::pair<std::string, std::string> parseUrl(const std::string& sUrl) {
  // Find scheme
  auto iSchemeEnd = sUrl.find("://");
  if (iSchemeEnd == std::string::npos) {
    throw common::ValidationError("INVALID_URL", "Invalid URL: " + sUrl);
  }
  auto iPathStart = sUrl.find('/', iSchemeEnd + 3);
  if (iPathStart == std::string::npos) {
    return {sUrl, "/"};
  }
  return {sUrl.substr(0, iPathStart), sUrl.substr(iPathStart)};
}

constexpr auto kStateTtl = std::chrono::minutes(10);
constexpr auto kDiscoveryCacheTtl = std::chrono::hours(1);

}  // anonymous namespace

// ── OidcService ────────────────────────────────────────────────────────────

OidcService::OidcService() = default;
OidcService::~OidcService() = default;

std::pair<std::string, std::string> OidcService::generatePkce() {
  // Generate 32 random bytes for verifier
  unsigned char vRandom[32];
  if (RAND_bytes(vRandom, sizeof(vRandom)) != 1) {
    throw std::runtime_error("RAND_bytes failed for PKCE verifier");
  }
  std::string sVerifier = base64UrlEncode(vRandom, sizeof(vRandom));

  // Challenge = base64url(SHA-256(verifier))
  std::string sHash = sha256Raw(sVerifier);
  std::string sChallenge = base64UrlEncode(
      reinterpret_cast<const unsigned char*>(sHash.data()), sHash.size());

  return {sVerifier, sChallenge};
}

std::string OidcService::generateState() {
  unsigned char vRandom[24];
  if (RAND_bytes(vRandom, sizeof(vRandom)) != 1) {
    throw std::runtime_error("RAND_bytes failed for OIDC state");
  }
  return base64UrlEncode(vRandom, sizeof(vRandom));
}

std::string OidcService::buildAuthorizationUrl(
    const std::string& sAuthEndpoint, const std::string& sClientId,
    const std::string& sRedirectUri, const std::string& sScope,
    const std::string& sState, const std::string& sCodeChallenge) {
  std::ostringstream oss;
  oss << sAuthEndpoint;
  oss << (sAuthEndpoint.find('?') != std::string::npos ? "&" : "?");
  oss << "response_type=code";
  oss << "&client_id=" << urlEncode(sClientId);
  oss << "&redirect_uri=" << urlEncode(sRedirectUri);
  oss << "&scope=" << urlEncode(sScope);
  oss << "&state=" << urlEncode(sState);
  oss << "&code_challenge=" << urlEncode(sCodeChallenge);
  oss << "&code_challenge_method=S256";
  return oss.str();
}

void OidcService::storeAuthState(const std::string& sState, OidcAuthState oaState) {
  std::lock_guard<std::mutex> lock(_mtxStates);
  evictExpiredStates();
  _mAuthStates.emplace(sState, std::move(oaState));
}

std::optional<OidcAuthState> OidcService::consumeAuthState(const std::string& sState) {
  std::lock_guard<std::mutex> lock(_mtxStates);
  evictExpiredStates();

  auto it = _mAuthStates.find(sState);
  if (it == _mAuthStates.end()) {
    return std::nullopt;
  }

  OidcAuthState oaState = std::move(it->second);
  _mAuthStates.erase(it);
  return oaState;
}

void OidcService::evictExpiredStates() {
  auto tpNow = std::chrono::system_clock::now();
  for (auto it = _mAuthStates.begin(); it != _mAuthStates.end();) {
    if (tpNow - it->second.tpCreatedAt > kStateTtl) {
      it = _mAuthStates.erase(it);
    } else {
      ++it;
    }
  }
}

OidcDiscovery OidcService::discover(const std::string& sIssuerUrl) {
  {
    std::lock_guard<std::mutex> lock(_mtxDiscovery);
    auto it = _mDiscoveryCache.find(sIssuerUrl);
    if (it != _mDiscoveryCache.end()) {
      auto tpAge = std::chrono::system_clock::now() - it->second.tpFetchedAt;
      if (tpAge < kDiscoveryCacheTtl) {
        return it->second;
      }
    }
  }

  // Fetch discovery document
  std::string sDiscoveryUrl = sIssuerUrl;
  if (!sDiscoveryUrl.empty() && sDiscoveryUrl.back() == '/') {
    sDiscoveryUrl.pop_back();
  }
  sDiscoveryUrl += "/.well-known/openid-configuration";

  auto [sHost, sPath] = parseUrl(sDiscoveryUrl);
  httplib::Client client(sHost);
  client.set_connection_timeout(10);
  client.set_read_timeout(10);

  auto res = client.Get(sPath);
  if (!res || res->status != 200) {
    throw common::AuthenticationError(
        "oidc_discovery_failed",
        "Failed to fetch OIDC discovery document from " + sDiscoveryUrl);
  }

  auto jDoc = nlohmann::json::parse(res->body);

  OidcDiscovery odDiscovery;
  odDiscovery.sAuthorizationEndpoint = jDoc.value("authorization_endpoint", "");
  odDiscovery.sTokenEndpoint = jDoc.value("token_endpoint", "");
  odDiscovery.sJwksUri = jDoc.value("jwks_uri", "");
  odDiscovery.sIssuer = jDoc.value("issuer", "");
  odDiscovery.tpFetchedAt = std::chrono::system_clock::now();

  if (odDiscovery.sAuthorizationEndpoint.empty() || odDiscovery.sTokenEndpoint.empty()) {
    throw common::AuthenticationError(
        "oidc_discovery_invalid",
        "OIDC discovery document missing required endpoints");
  }

  {
    std::lock_guard<std::mutex> lock(_mtxDiscovery);
    _mDiscoveryCache[sIssuerUrl] = odDiscovery;
  }

  spdlog::info("OIDC discovery fetched for issuer: {}", sIssuerUrl);
  return odDiscovery;
}

// ── Task 5: Token Exchange & JWT Validation ────────────────────────────────

nlohmann::json OidcService::exchangeCode(const std::string& sTokenEndpoint,
                                         const std::string& sCode,
                                         const std::string& sClientId,
                                         const std::string& sClientSecret,
                                         const std::string& sRedirectUri,
                                         const std::string& sCodeVerifier) {
  auto [sHost, sPath] = parseUrl(sTokenEndpoint);
  httplib::Client client(sHost);
  client.set_connection_timeout(10);
  client.set_read_timeout(10);

  httplib::Params params;
  params.emplace("grant_type", "authorization_code");
  params.emplace("code", sCode);
  params.emplace("client_id", sClientId);
  params.emplace("redirect_uri", sRedirectUri);
  params.emplace("code_verifier", sCodeVerifier);
  if (!sClientSecret.empty()) {
    params.emplace("client_secret", sClientSecret);
  }

  auto res = client.Post(sPath, params);
  if (!res) {
    throw common::AuthenticationError(
        "oidc_token_exchange_failed",
        "Failed to connect to token endpoint: " + sTokenEndpoint);
  }
  if (res->status != 200) {
    spdlog::error("OIDC token exchange failed: status={}, body={}", res->status, res->body);
    throw common::AuthenticationError(
        "oidc_token_exchange_failed",
        "Token exchange failed with status " + std::to_string(res->status));
  }

  return nlohmann::json::parse(res->body);
}

nlohmann::json OidcService::validateIdToken(const std::string& sIdToken,
                                            const std::string& sJwksUri,
                                            const std::string& sExpectedIssuer,
                                            const std::string& sExpectedAudience) {
  // Split JWT into header.payload.signature
  auto iDot1 = sIdToken.find('.');
  if (iDot1 == std::string::npos) {
    throw common::AuthenticationError("invalid_id_token", "Invalid JWT format");
  }
  auto iDot2 = sIdToken.find('.', iDot1 + 1);
  if (iDot2 == std::string::npos) {
    throw common::AuthenticationError("invalid_id_token", "Invalid JWT format");
  }

  std::string sHeaderB64 = sIdToken.substr(0, iDot1);
  std::string sPayloadB64 = sIdToken.substr(iDot1 + 1, iDot2 - iDot1 - 1);
  std::string sSignatureB64 = sIdToken.substr(iDot2 + 1);

  // Decode header to get kid and alg
  auto jHeader = nlohmann::json::parse(base64UrlDecode(sHeaderB64));
  std::string sAlg = jHeader.value("alg", "");
  std::string sKid = jHeader.value("kid", "");

  // Fetch JWKS
  auto [sHost, sPath] = parseUrl(sJwksUri);
  httplib::Client client(sHost);
  client.set_connection_timeout(10);
  client.set_read_timeout(10);

  auto res = client.Get(sPath);
  if (!res || res->status != 200) {
    throw common::AuthenticationError("jwks_fetch_failed", "Failed to fetch JWKS");
  }

  auto jJwks = nlohmann::json::parse(res->body);
  auto& jKeys = jJwks["keys"];

  // Find matching key
  nlohmann::json jMatchingKey;
  for (const auto& jKey : jKeys) {
    if (!sKid.empty() && jKey.value("kid", "") == sKid) {
      jMatchingKey = jKey;
      break;
    }
    if (sKid.empty() && jKey.value("alg", "") == sAlg) {
      jMatchingKey = jKey;
      break;
    }
  }

  if (jMatchingKey.is_null()) {
    throw common::AuthenticationError("jwks_key_not_found",
                                      "No matching key found in JWKS for kid=" + sKid);
  }

  // Verify signature
  std::string sSigningInput = sHeaderB64 + "." + sPayloadB64;
  auto vSignature = base64UrlDecodeBytes(sSignatureB64);

  EVP_PKEY* pKey = nullptr;

  if (sAlg == "RS256") {
    // Construct RSA public key from JWK n and e using OpenSSL 3.0 API
    auto vN = base64UrlDecodeBytes(jMatchingKey["n"].get<std::string>());
    auto vE = base64UrlDecodeBytes(jMatchingKey["e"].get<std::string>());

    BIGNUM* pBnN = BN_bin2bn(vN.data(), static_cast<int>(vN.size()), nullptr);
    BIGNUM* pBnE = BN_bin2bn(vE.data(), static_cast<int>(vE.size()), nullptr);

    OSSL_PARAM_BLD* pBld = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_BN(pBld, OSSL_PKEY_PARAM_RSA_N, pBnN);
    OSSL_PARAM_BLD_push_BN(pBld, OSSL_PKEY_PARAM_RSA_E, pBnE);
    OSSL_PARAM* pParams = OSSL_PARAM_BLD_to_param(pBld);

    EVP_PKEY_CTX* pCtx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
    EVP_PKEY_fromdata_init(pCtx);
    EVP_PKEY_fromdata(pCtx, &pKey, EVP_PKEY_PUBLIC_KEY, pParams);

    EVP_PKEY_CTX_free(pCtx);
    OSSL_PARAM_free(pParams);
    OSSL_PARAM_BLD_free(pBld);
    BN_free(pBnN);
    BN_free(pBnE);

  } else if (sAlg == "ES256") {
    // Construct EC public key from JWK x and y using OpenSSL 3.0 API
    auto vX = base64UrlDecodeBytes(jMatchingKey["x"].get<std::string>());
    auto vY = base64UrlDecodeBytes(jMatchingKey["y"].get<std::string>());

    // Build uncompressed point: 0x04 || x || y
    std::vector<unsigned char> vPub;
    vPub.reserve(1 + vX.size() + vY.size());
    vPub.push_back(0x04);
    vPub.insert(vPub.end(), vX.begin(), vX.end());
    vPub.insert(vPub.end(), vY.begin(), vY.end());

    OSSL_PARAM_BLD* pBld = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_utf8_string(pBld, OSSL_PKEY_PARAM_GROUP_NAME,
                                    "prime256v1", 0);
    OSSL_PARAM_BLD_push_octet_string(pBld, OSSL_PKEY_PARAM_PUB_KEY,
                                     vPub.data(), vPub.size());
    OSSL_PARAM* pParams = OSSL_PARAM_BLD_to_param(pBld);

    EVP_PKEY_CTX* pCtx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    EVP_PKEY_fromdata_init(pCtx);
    EVP_PKEY_fromdata(pCtx, &pKey, EVP_PKEY_PUBLIC_KEY, pParams);

    EVP_PKEY_CTX_free(pCtx);
    OSSL_PARAM_free(pParams);
    OSSL_PARAM_BLD_free(pBld);

    // ES256 signature is r||s (64 bytes), need to convert to DER for OpenSSL
    if (vSignature.size() == 64) {
      // Manually build DER-encoded ECDSA signature
      // SEQUENCE { INTEGER r, INTEGER s }
      auto buildDerInt = [](const unsigned char* pData, size_t uLen) {
        std::vector<unsigned char> vInt;
        // Skip leading zeros but keep at least one byte
        size_t uStart = 0;
        while (uStart < uLen - 1 && pData[uStart] == 0) ++uStart;
        bool bNeedPad = (pData[uStart] & 0x80) != 0;
        vInt.push_back(0x02);  // INTEGER tag
        vInt.push_back(static_cast<unsigned char>(uLen - uStart + (bNeedPad ? 1 : 0)));
        if (bNeedPad) vInt.push_back(0x00);
        vInt.insert(vInt.end(), pData + uStart, pData + uLen);
        return vInt;
      };

      auto vR = buildDerInt(vSignature.data(), 32);
      auto vS = buildDerInt(vSignature.data() + 32, 32);

      std::vector<unsigned char> vDer;
      vDer.push_back(0x30);  // SEQUENCE tag
      vDer.push_back(static_cast<unsigned char>(vR.size() + vS.size()));
      vDer.insert(vDer.end(), vR.begin(), vR.end());
      vDer.insert(vDer.end(), vS.begin(), vS.end());
      vSignature = std::move(vDer);
    }
  } else {
    throw common::AuthenticationError("unsupported_alg",
                                      "Unsupported JWT algorithm: " + sAlg);
  }

  // Verify with EVP_DigestVerify
  EVP_MD_CTX* pMdCtx = EVP_MD_CTX_new();
  bool bValid = false;

  if (EVP_DigestVerifyInit(pMdCtx, nullptr, EVP_sha256(), nullptr, pKey) == 1) {
    if (EVP_DigestVerifyUpdate(pMdCtx, sSigningInput.data(), sSigningInput.size()) == 1) {
      bValid = (EVP_DigestVerifyFinal(pMdCtx, vSignature.data(), vSignature.size()) == 1);
    }
  }

  EVP_MD_CTX_free(pMdCtx);
  EVP_PKEY_free(pKey);

  if (!bValid) {
    throw common::AuthenticationError("invalid_signature", "ID token signature verification failed");
  }

  // Decode and validate payload claims
  auto jPayload = nlohmann::json::parse(base64UrlDecode(sPayloadB64));
  validateIdTokenClaims(jPayload, sExpectedIssuer, sExpectedAudience);

  return jPayload;
}

void OidcService::validateIdTokenClaims(const nlohmann::json& jPayload,
                                        const std::string& sExpectedIssuer,
                                        const std::string& sExpectedAudience) {
  // Validate issuer
  std::string sIss = jPayload.value("iss", "");
  if (sIss != sExpectedIssuer) {
    throw common::AuthenticationError(
        "invalid_issuer",
        "ID token issuer mismatch: expected " + sExpectedIssuer + ", got " + sIss);
  }

  // Validate audience — can be string or array
  bool bAudMatch = false;
  if (jPayload.contains("aud")) {
    if (jPayload["aud"].is_string()) {
      bAudMatch = (jPayload["aud"].get<std::string>() == sExpectedAudience);
    } else if (jPayload["aud"].is_array()) {
      for (const auto& aud : jPayload["aud"]) {
        if (aud.get<std::string>() == sExpectedAudience) {
          bAudMatch = true;
          break;
        }
      }
    }
  }
  if (!bAudMatch) {
    throw common::AuthenticationError(
        "invalid_audience", "ID token audience does not contain expected client_id");
  }

  // Validate expiry
  auto iNow = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();
  int64_t iExp = jPayload.value("exp", static_cast<int64_t>(0));
  if (iExp <= iNow) {
    throw common::AuthenticationError("token_expired", "ID token has expired");
  }
}

}  // namespace dns::security
