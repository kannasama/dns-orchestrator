#pragma once

#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

#include <nlohmann/json.hpp>

namespace dns::security {

class SamlReplayCache;

/// State stored during SAML authorization flow (between redirect and ACS callback).
struct SamlAuthState {
  int64_t iIdpId = 0;
  std::string sRequestId;  // ID from AuthnRequest for InResponseTo validation
  bool bIsTestMode = false;
  std::chrono::system_clock::time_point tpCreatedAt;
};

/// Handles SAML 2.0 protocol operations: AuthnRequest generation, assertion validation.
/// Class abbreviation: ss
class SamlService {
 public:
  explicit SamlService(SamlReplayCache& srcCache);
  ~SamlService();

  /// Generate a SAML AuthnRequest XML document.
  std::string generateAuthnRequest(const std::string& sSpEntityId,
                                   const std::string& sAcsUrl,
                                   const std::string& sIdpSsoUrl);

  /// Build the SSO redirect URL with deflated, base64-encoded AuthnRequest.
  std::string buildRedirectUrl(const std::string& sIdpSsoUrl,
                               const std::string& sAuthnRequest,
                               const std::string& sRelayState);

  void storeAuthState(const std::string& sRelayState, SamlAuthState saState);
  std::optional<SamlAuthState> consumeAuthState(const std::string& sRelayState);

  /// Parse and validate a SAML Response/Assertion.
  /// Returns decoded attributes as JSON on success.
  /// If sIdpCertPem is empty, signature verification is skipped (for unit tests).
  nlohmann::json validateAssertion(const std::string& sSamlResponse,
                                   const std::string& sIdpCertPem,
                                   const std::string& sExpectedAudience,
                                   const std::string& sExpectedRequestId);

  /// Base64 encode a string (used by tests to construct SAML responses).
  static std::string base64Encode(const std::string& sInput);

  /// Format a time_point as ISO 8601 UTC string (used by tests).
  static std::string formatIso8601(std::chrono::system_clock::time_point tp);

 private:
  void evictExpiredStates();

  /// Extract text content between XML tags.
  static std::string extractElement(const std::string& sXml, const std::string& sTag);

  /// Extract an XML attribute value.
  static std::string extractAttribute(const std::string& sXml, const std::string& sAttr);

  /// Extract all values for a named SAML attribute.
  static std::vector<std::string> extractAttributeValues(const std::string& sXml,
                                                         const std::string& sAttrName);

  /// Parse ISO 8601 timestamp to time_point.
  static std::chrono::system_clock::time_point parseIso8601(const std::string& sTimestamp);

  SamlReplayCache& _srcCache;
  std::mutex _mtxStates;
  std::unordered_map<std::string, SamlAuthState> _mAuthStates;
};

}  // namespace dns::security
