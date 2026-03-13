#include "security/SamlService.hpp"

#include "common/Errors.hpp"
#include "security/SamlReplayCache.hpp"

#include <spdlog/spdlog.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include <spdlog/spdlog.h>

#include <zlib.h>

#include <algorithm>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <vector>

namespace dns::security {

namespace {

constexpr auto kStateTtl = std::chrono::minutes(10);

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

std::string generateRandomHex(int iBytes) {
  std::vector<unsigned char> vRandom(static_cast<size_t>(iBytes));
  if (RAND_bytes(vRandom.data(), iBytes) != 1) {
    throw std::runtime_error("RAND_bytes failed");
  }
  std::ostringstream oss;
  for (unsigned char c : vRandom) {
    oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(c);
  }
  return oss.str();
}

/// Deflate (raw, no zlib header) for SAML HTTP-Redirect binding.
std::vector<unsigned char> deflateRaw(const std::string& sInput) {
  z_stream zs{};
  // -MAX_WBITS for raw deflate (no zlib/gzip header)
  if (deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -MAX_WBITS, 8,
                   Z_DEFAULT_STRATEGY) != Z_OK) {
    throw std::runtime_error("deflateInit2 failed");
  }

  zs.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(sInput.data()));
  zs.avail_in = static_cast<uInt>(sInput.size());

  std::vector<unsigned char> vOut(sInput.size() + 128);
  zs.next_out = vOut.data();
  zs.avail_out = static_cast<uInt>(vOut.size());

  int iRet = deflate(&zs, Z_FINISH);
  deflateEnd(&zs);

  if (iRet != Z_STREAM_END) {
    throw std::runtime_error("deflate failed");
  }

  vOut.resize(zs.total_out);
  return vOut;
}

/// Base64 encode raw bytes.
std::string base64EncodeBytes(const unsigned char* pData, size_t uLen) {
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

  std::string sResult(reinterpret_cast<char*>(vOut.data()), static_cast<size_t>(iTotalLen));
  std::erase(sResult, '\n');
  return sResult;
}

/// Base64 decode to string.
std::string base64DecodeStr(const std::string& sInput) {
  EVP_ENCODE_CTX* pCtx = EVP_ENCODE_CTX_new();
  EVP_DecodeInit(pCtx);

  std::vector<unsigned char> vOut(sInput.size());
  int iOutLen = 0;
  int iTotalLen = 0;

  int iRet = EVP_DecodeUpdate(pCtx, vOut.data(), &iOutLen,
                              reinterpret_cast<const unsigned char*>(sInput.data()),
                              static_cast<int>(sInput.size()));
  if (iRet < 0) {
    EVP_ENCODE_CTX_free(pCtx);
    throw common::AuthenticationError("invalid_saml", "Failed to decode SAML response");
  }
  iTotalLen += iOutLen;
  EVP_DecodeFinal(pCtx, vOut.data() + iTotalLen, &iOutLen);
  iTotalLen += iOutLen;
  EVP_ENCODE_CTX_free(pCtx);

  return std::string(reinterpret_cast<char*>(vOut.data()), static_cast<size_t>(iTotalLen));
}

}  // anonymous namespace

// ── SamlService ────────────────────────────────────────────────────────────

SamlService::SamlService(SamlReplayCache& srcCache) : _srcCache(srcCache) {}
SamlService::~SamlService() = default;

std::string SamlService::base64Encode(const std::string& sInput) {
  return base64EncodeBytes(reinterpret_cast<const unsigned char*>(sInput.data()),
                           sInput.size());
}

std::string SamlService::formatIso8601(std::chrono::system_clock::time_point tp) {
  auto tTime = std::chrono::system_clock::to_time_t(tp);
  std::tm tmUtc{};
  gmtime_r(&tTime, &tmUtc);
  std::ostringstream oss;
  oss << std::put_time(&tmUtc, "%Y-%m-%dT%H:%M:%SZ");
  return oss.str();
}

std::chrono::system_clock::time_point SamlService::parseIso8601(const std::string& sTimestamp) {
  std::tm tmParsed{};
  std::istringstream iss(sTimestamp);
  iss >> std::get_time(&tmParsed, "%Y-%m-%dT%H:%M:%S");
  if (iss.fail()) {
    throw common::AuthenticationError("invalid_timestamp",
                                      "Failed to parse SAML timestamp: " + sTimestamp);
  }
  auto tTime = timegm(&tmParsed);
  return std::chrono::system_clock::from_time_t(tTime);
}

// ── Task 6: AuthnRequest generation ────────────────────────────────────────

std::string SamlService::generateAuthnRequest(const std::string& sSpEntityId,
                                              const std::string& sAcsUrl,
                                              const std::string& sIdpSsoUrl) {
  std::string sId = "_" + generateRandomHex(16);
  std::string sIssueInstant = formatIso8601(std::chrono::system_clock::now());

  std::ostringstream oss;
  oss << "<samlp:AuthnRequest"
      << " xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\""
      << " xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\""
      << " ID=\"" << sId << "\""
      << " Version=\"2.0\""
      << " IssueInstant=\"" << sIssueInstant << "\""
      << " Destination=\"" << sIdpSsoUrl << "\""
      << " AssertionConsumerServiceURL=\"" << sAcsUrl << "\""
      << " ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\""
      << ">"
      << "<saml:Issuer>" << sSpEntityId << "</saml:Issuer>"
      << "</samlp:AuthnRequest>";

  return oss.str();
}

std::string SamlService::buildRedirectUrl(const std::string& sIdpSsoUrl,
                                          const std::string& sAuthnRequest,
                                          const std::string& sRelayState) {
  // Deflate the AuthnRequest
  auto vDeflated = deflateRaw(sAuthnRequest);

  // Base64 encode
  std::string sEncoded = base64EncodeBytes(vDeflated.data(), vDeflated.size());

  // Build URL
  std::ostringstream oss;
  oss << sIdpSsoUrl;
  oss << (sIdpSsoUrl.find('?') != std::string::npos ? "&" : "?");
  oss << "SAMLRequest=" << urlEncode(sEncoded);
  if (!sRelayState.empty()) {
    oss << "&RelayState=" << urlEncode(sRelayState);
  }
  return oss.str();
}

void SamlService::storeAuthState(const std::string& sRelayState, SamlAuthState saState) {
  std::lock_guard<std::mutex> lock(_mtxStates);
  evictExpiredStates();
  _mAuthStates.emplace(sRelayState, std::move(saState));
}

std::optional<SamlAuthState> SamlService::consumeAuthState(const std::string& sRelayState) {
  std::lock_guard<std::mutex> lock(_mtxStates);
  evictExpiredStates();

  auto it = _mAuthStates.find(sRelayState);
  if (it == _mAuthStates.end()) {
    return std::nullopt;
  }

  SamlAuthState saState = std::move(it->second);
  _mAuthStates.erase(it);
  return saState;
}

void SamlService::evictExpiredStates() {
  auto tpNow = std::chrono::system_clock::now();
  for (auto it = _mAuthStates.begin(); it != _mAuthStates.end();) {
    if (tpNow - it->second.tpCreatedAt > kStateTtl) {
      it = _mAuthStates.erase(it);
    } else {
      ++it;
    }
  }
}

// ── Task 7: Assertion validation ───────────────────────────────────────────

std::string SamlService::extractElement(const std::string& sXml, const std::string& sTag) {
  // Find opening tag (may have attributes)
  std::string sOpenPrefix = "<" + sTag;
  size_t iSearchFrom = 0;
  size_t iStart = std::string::npos;
  while (true) {
    iStart = sXml.find(sOpenPrefix, iSearchFrom);
    if (iStart == std::string::npos) return "";
    // Ensure we matched the exact tag, not a prefix (e.g. "saml:Audience" vs "saml:AudienceRestriction")
    auto iAfterTag = iStart + sOpenPrefix.size();
    if (iAfterTag < sXml.size()) {
      char cNext = sXml[iAfterTag];
      if (cNext == '>' || cNext == ' ' || cNext == '/' || cNext == '\t' || cNext == '\n' || cNext == '\r') {
        break;  // Exact match
      }
    } else {
      return "";  // Tag at end of string, malformed
    }
    iSearchFrom = iStart + 1;
  }

  // Find end of opening tag
  auto iTagEnd = sXml.find('>', iStart);
  if (iTagEnd == std::string::npos) return "";

  // Check for self-closing tag
  if (sXml[iTagEnd - 1] == '/') return "";

  auto iContentStart = iTagEnd + 1;

  // Find closing tag
  std::string sCloseTag = "</" + sTag + ">";
  auto iEnd = sXml.find(sCloseTag, iContentStart);
  if (iEnd == std::string::npos) return "";

  return sXml.substr(iContentStart, iEnd - iContentStart);
}

std::string SamlService::extractAttribute(const std::string& sXml, const std::string& sAttr) {
  std::string sSearch = sAttr + "=\"";
  auto iStart = sXml.find(sSearch);
  if (iStart == std::string::npos) return "";

  auto iValueStart = iStart + sSearch.size();
  auto iEnd = sXml.find('"', iValueStart);
  if (iEnd == std::string::npos) return "";

  return sXml.substr(iValueStart, iEnd - iValueStart);
}

/// Detect the namespace prefix used for SAML assertion elements.
/// Tries "saml:", "saml2:", and no prefix. Returns the prefix string (e.g. "saml:", "saml2:", "").
std::string detectAssertionPrefix(const std::string& sXml) {
  for (const auto& sPrefix : {"saml:", "saml2:", ""}) {
    std::string sSearch = std::string("<") + sPrefix + "Assertion";
    auto iPos = sXml.find(sSearch);
    if (iPos != std::string::npos) {
      // Verify exact tag match (not a prefix of a longer tag name)
      auto iAfter = iPos + sSearch.size();
      if (iAfter < sXml.size()) {
        char c = sXml[iAfter];
        if (c == '>' || c == ' ' || c == '/' || c == '\t' || c == '\n' || c == '\r') {
          return sPrefix;
        }
      }
    }
  }
  return "saml:";  // fallback
}

/// Find the closing tag for an element, trying multiple namespace prefixes.
/// Returns the position after the closing tag, or npos if not found.
size_t findClosingTag(const std::string& sXml, const std::string& sLocalName,
                      const std::string& sPrefix, size_t iFrom) {
  std::string sClose = "</" + sPrefix + sLocalName + ">";
  return sXml.find(sClose, iFrom);
}

std::vector<std::string> SamlService::extractAttributeValues(const std::string& sXml,
                                                             const std::string& sAttrName) {
  std::vector<std::string> vValues;

  // Find the Attribute element with the given Name
  std::string sSearch = "Name=\"" + sAttrName + "\"";
  auto iAttrStart = sXml.find(sSearch);
  if (iAttrStart == std::string::npos) return vValues;

  // Detect prefix used in this context
  std::string sPrefix = detectAssertionPrefix(sXml);

  // Find the end of this Attribute element (try detected prefix, then alternatives)
  std::string sCloseTag = "</" + sPrefix + "Attribute>";
  auto iAttrEnd = sXml.find(sCloseTag, iAttrStart);
  if (iAttrEnd == std::string::npos) {
    // Try without prefix
    iAttrEnd = sXml.find("</Attribute>", iAttrStart);
    if (iAttrEnd == std::string::npos) return vValues;
  }

  std::string sAttrBlock = sXml.substr(iAttrStart, iAttrEnd - iAttrStart);

  // Extract all AttributeValue elements — try with prefix first, then without
  // Also handle AttributeValue tags that may have attributes (e.g. xsi:type)
  size_t iPos = 0;
  while (true) {
    // Find opening AttributeValue tag with any prefix
    size_t iValTagStart = std::string::npos;
    for (const auto& p : {sPrefix, std::string("")}) {
      std::string sTag = "<" + p + "AttributeValue";
      auto iFound = sAttrBlock.find(sTag, iPos);
      if (iFound != std::string::npos && (iValTagStart == std::string::npos || iFound < iValTagStart)) {
        iValTagStart = iFound;
      }
    }
    if (iValTagStart == std::string::npos) break;

    // Find end of opening tag (may have attributes like xsi:type)
    auto iValContentStart = sAttrBlock.find('>', iValTagStart);
    if (iValContentStart == std::string::npos) break;
    iValContentStart += 1;

    // Find closing tag
    size_t iValEnd = std::string::npos;
    for (const auto& p : {sPrefix, std::string("")}) {
      std::string sClose = "</" + p + "AttributeValue>";
      auto iFound = sAttrBlock.find(sClose, iValContentStart);
      if (iFound != std::string::npos && (iValEnd == std::string::npos || iFound < iValEnd)) {
        iValEnd = iFound;
      }
    }
    if (iValEnd == std::string::npos) break;

    vValues.push_back(sAttrBlock.substr(iValContentStart, iValEnd - iValContentStart));
    iPos = iValEnd + 1;
  }

  return vValues;
}

nlohmann::json SamlService::validateAssertion(const std::string& sSamlResponse,
                                              const std::string& sIdpCertPem,
                                              const std::string& sExpectedAudience,
                                              const std::string& sExpectedRequestId) {
  // 1. Base64-decode the SAMLResponse
  std::string sXml = base64DecodeStr(sSamlResponse);

  // Detect the namespace prefix used for SAML assertion elements
  std::string sP = detectAssertionPrefix(sXml);
  spdlog::debug("SAML assertion namespace prefix: '{}'", sP);

  // 2. Check status — the StatusCode Value attribute contains "Success"
  std::string sStatusCode = extractAttribute(sXml, "Value");
  if (sStatusCode.find("Success") == std::string::npos) {
    throw common::AuthenticationError("saml_status_failed",
                                      "SAML response status is not Success: " + sStatusCode);
  }

  // 3. Extract assertion (try detected prefix)
  std::string sAssertion = extractElement(sXml, sP + "Assertion");
  if (sAssertion.empty()) {
    spdlog::error("No assertion found with prefix '{}'. XML snippet (first 500 chars): {}",
                  sP, sXml.substr(0, 500));
    throw common::AuthenticationError("saml_no_assertion", "No assertion found in SAML response");
  }

  // 4. Extract assertion ID for replay check
  // Find the Assertion element to get its ID attribute
  auto iAssertionStart = sXml.find("<" + sP + "Assertion");
  std::string sAssertionTag = sXml.substr(iAssertionStart,
                                          sXml.find('>', iAssertionStart) - iAssertionStart + 1);
  std::string sAssertionId = extractAttribute(sAssertionTag, "ID");

  // 5. Validate conditions
  std::string sConditions;
  std::string sCondTag = sP + "Conditions";
  auto iCondStart = sAssertion.find("<" + sCondTag);
  if (iCondStart != std::string::npos) {
    std::string sCondClose = "</" + sCondTag + ">";
    auto iCondEnd = sAssertion.find(sCondClose, iCondStart);
    if (iCondEnd != std::string::npos) {
      sConditions = sAssertion.substr(iCondStart, iCondEnd - iCondStart + sCondClose.size());
    }
  }

  if (!sConditions.empty()) {
    std::string sNotBefore = extractAttribute(sConditions, "NotBefore");
    std::string sNotOnOrAfter = extractAttribute(sConditions, "NotOnOrAfter");

    auto tpNow = std::chrono::system_clock::now();

    if (!sNotBefore.empty()) {
      auto tpNotBefore = parseIso8601(sNotBefore);
      // Allow 60 seconds clock skew
      if (tpNow < tpNotBefore - std::chrono::seconds(60)) {
        throw common::AuthenticationError("saml_not_yet_valid",
                                          "SAML assertion is not yet valid");
      }
    }

    if (!sNotOnOrAfter.empty()) {
      auto tpNotOnOrAfter = parseIso8601(sNotOnOrAfter);
      if (tpNow > tpNotOnOrAfter + std::chrono::seconds(60)) {
        throw common::AuthenticationError("saml_expired", "SAML assertion has expired");
      }
    }

    // Validate audience
    std::string sAudience = extractElement(sConditions, sP + "Audience");
    if (!sAudience.empty() && sAudience != sExpectedAudience) {
      throw common::AuthenticationError(
          "saml_audience_mismatch",
          "SAML audience mismatch: expected " + sExpectedAudience + ", got " + sAudience);
    }
  }

  // 6. Validate InResponseTo
  if (!sExpectedRequestId.empty()) {
    std::string sInResponseTo = extractAttribute(sAssertion, "InResponseTo");
    if (!sInResponseTo.empty() && sInResponseTo != sExpectedRequestId) {
      throw common::AuthenticationError(
          "saml_request_id_mismatch",
          "SAML InResponseTo mismatch: expected " + sExpectedRequestId);
    }
  }

  // 7. Verify XML signature (if certificate provided)
  if (!sIdpCertPem.empty()) {
    // Extract SignatureValue and SignedInfo for verification
    std::string sSignatureValue = extractElement(sXml, "ds:SignatureValue");
    if (sSignatureValue.empty()) {
      // Try without namespace prefix
      sSignatureValue = extractElement(sXml, "SignatureValue");
    }

    if (!sSignatureValue.empty()) {
      // Find SignedInfo element (canonicalized)
      std::string sSignedInfo;
      auto iSiStart = sXml.find("<ds:SignedInfo");
      if (iSiStart == std::string::npos) iSiStart = sXml.find("<SignedInfo");
      if (iSiStart != std::string::npos) {
        std::string sCloseTag = "</ds:SignedInfo>";
        auto iSiEnd = sXml.find(sCloseTag, iSiStart);
        if (iSiEnd == std::string::npos) {
          sCloseTag = "</SignedInfo>";
          iSiEnd = sXml.find(sCloseTag, iSiStart);
        }
        if (iSiEnd != std::string::npos) {
          sSignedInfo = sXml.substr(iSiStart, iSiEnd + sCloseTag.size() - iSiStart);
        }
      }

      if (!sSignedInfo.empty()) {
        // Load certificate
        BIO* pBio = BIO_new_mem_buf(sIdpCertPem.data(),
                                    static_cast<int>(sIdpCertPem.size()));
        X509* pCert = PEM_read_bio_X509(pBio, nullptr, nullptr, nullptr);
        BIO_free(pBio);

        if (pCert) {
          EVP_PKEY* pKey = X509_get_pubkey(pCert);

          // Decode signature from base64
          // Remove whitespace from signature value
          std::string sSigClean;
          for (char c : sSignatureValue) {
            if (!std::isspace(static_cast<unsigned char>(c))) {
              sSigClean += c;
            }
          }
          std::string sSigBytes = base64DecodeStr(sSigClean);

          // Verify
          EVP_MD_CTX* pMdCtx = EVP_MD_CTX_new();
          bool bValid = false;

          if (EVP_DigestVerifyInit(pMdCtx, nullptr, EVP_sha256(), nullptr, pKey) == 1) {
            if (EVP_DigestVerifyUpdate(pMdCtx, sSignedInfo.data(), sSignedInfo.size()) == 1) {
              bValid = (EVP_DigestVerifyFinal(
                            pMdCtx,
                            reinterpret_cast<const unsigned char*>(sSigBytes.data()),
                            sSigBytes.size()) == 1);
            }
          }

          EVP_MD_CTX_free(pMdCtx);
          EVP_PKEY_free(pKey);
          X509_free(pCert);

          if (!bValid) {
            throw common::AuthenticationError("saml_signature_invalid",
                                              "SAML assertion signature verification failed");
          }
        } else {
          throw common::AuthenticationError("saml_cert_invalid",
                                            "Failed to parse IdP certificate");
        }
      }
    }
  }

  // 8. Check replay
  if (!sAssertionId.empty()) {
    auto tpExpiry = std::chrono::system_clock::now() + std::chrono::hours(1);
    std::string sNotOnOrAfter = extractAttribute(sAssertion, "NotOnOrAfter");
    if (!sNotOnOrAfter.empty()) {
      tpExpiry = parseIso8601(sNotOnOrAfter);
    }
    if (!_srcCache.checkAndInsert(sAssertionId, tpExpiry)) {
      throw common::AuthenticationError("saml_replay", "SAML assertion replay detected");
    }
  }

  // 9. Extract NameID and attributes
  std::string sNameId = extractElement(sAssertion, sP + "NameID");

  nlohmann::json jAttributes = nlohmann::json::object();

  // Find all Attribute elements
  std::string sAttrStatement = extractElement(sAssertion, sP + "AttributeStatement");
  if (!sAttrStatement.empty()) {
    // Find each Attribute Name
    std::string sAttrOpen = "<" + sP + "Attribute ";
    size_t iPos = 0;
    while (true) {
      auto iAttrStart = sAttrStatement.find(sAttrOpen, iPos);
      if (iAttrStart == std::string::npos) break;

      auto iAttrTagEnd = sAttrStatement.find('>', iAttrStart);
      if (iAttrTagEnd == std::string::npos) break;

      std::string sAttrTag = sAttrStatement.substr(iAttrStart,
                                                    iAttrTagEnd - iAttrStart + 1);
      std::string sName = extractAttribute(sAttrTag, "Name");

      if (!sName.empty()) {
        auto vValues = extractAttributeValues(sAttrStatement, sName);
        nlohmann::json jValues = nlohmann::json::array();
        for (const auto& sVal : vValues) {
          jValues.push_back(sVal);
        }
        jAttributes[sName] = jValues;
      }

      iPos = iAttrTagEnd + 1;
    }
  }

  return {
      {"name_id", sNameId},
      {"attributes", jAttributes},
  };
}

}  // namespace dns::security
