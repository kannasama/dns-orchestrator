#pragma once

#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

#include <nlohmann/json.hpp>

namespace dns::security {

/// State stored during OIDC authorization flow (between redirect and callback).
struct OidcAuthState {
  std::string sCodeVerifier;
  int64_t iIdpId = 0;
  bool bIsTestMode = false;
  std::chrono::system_clock::time_point tpCreatedAt;
};

/// Cached OIDC discovery document.
struct OidcDiscovery {
  std::string sAuthorizationEndpoint;
  std::string sTokenEndpoint;
  std::string sJwksUri;
  std::string sIssuer;
  std::chrono::system_clock::time_point tpFetchedAt;
};

/// Handles OIDC protocol operations: discovery, PKCE, token exchange, JWT validation.
/// Class abbreviation: os
class OidcService {
 public:
  OidcService();
  ~OidcService();

  /// Generate PKCE code_verifier and code_challenge (S256).
  /// Returns {verifier, challenge}.
  static std::pair<std::string, std::string> generatePkce();

  /// Generate a random state string for CSRF prevention.
  static std::string generateState();

  /// Build the authorization URL with all required query parameters.
  static std::string buildAuthorizationUrl(
      const std::string& sAuthEndpoint, const std::string& sClientId,
      const std::string& sRedirectUri, const std::string& sScope,
      const std::string& sState, const std::string& sCodeChallenge);

  /// Store auth state keyed by state string.
  void storeAuthState(const std::string& sState, OidcAuthState oaState);

  /// Consume (retrieve and remove) auth state. Returns nullopt if not found or expired.
  std::optional<OidcAuthState> consumeAuthState(const std::string& sState);

  /// Fetch and cache the OIDC discovery document from the issuer.
  OidcDiscovery discover(const std::string& sIssuerUrl);

  /// Exchange an authorization code for tokens.
  /// Returns the parsed JSON response (access_token, id_token, token_type).
  nlohmann::json exchangeCode(const std::string& sTokenEndpoint,
                              const std::string& sCode,
                              const std::string& sClientId,
                              const std::string& sClientSecret,
                              const std::string& sRedirectUri,
                              const std::string& sCodeVerifier);

  /// Validate an ID token JWT: verify signature against JWKS, validate claims.
  /// Returns the decoded payload JSON.
  nlohmann::json validateIdToken(const std::string& sIdToken,
                                 const std::string& sJwksUri,
                                 const std::string& sExpectedIssuer,
                                 const std::string& sExpectedAudience);

  /// Validate ID token claims only (issuer, audience, expiry).
  /// Used by unit tests and internally after signature verification.
  void validateIdTokenClaims(const nlohmann::json& jPayload,
                             const std::string& sExpectedIssuer,
                             const std::string& sExpectedAudience);

 private:
  void evictExpiredStates();

  std::mutex _mtxStates;
  std::unordered_map<std::string, OidcAuthState> _mAuthStates;

  std::mutex _mtxDiscovery;
  std::unordered_map<std::string, OidcDiscovery> _mDiscoveryCache;
};

}  // namespace dns::security
