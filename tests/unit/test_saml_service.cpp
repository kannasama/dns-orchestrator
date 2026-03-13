#include "security/SamlService.hpp"

#include "common/Errors.hpp"
#include "security/SamlReplayCache.hpp"

#include <gtest/gtest.h>

#include <string>

using dns::security::SamlAuthState;
using dns::security::SamlReplayCache;
using dns::security::SamlService;

class SamlServiceTest : public ::testing::Test {
 protected:
  void SetUp() override {
    _upCache = std::make_unique<SamlReplayCache>();
    _upService = std::make_unique<SamlService>(*_upCache);
  }

  std::unique_ptr<SamlReplayCache> _upCache;
  std::unique_ptr<SamlService> _upService;
};

// ── Task 6: AuthnRequest generation tests ──────────────────────────────────

TEST_F(SamlServiceTest, GenerateAuthnRequest) {
  std::string sXml = _upService->generateAuthnRequest(
      "https://meridian.example.com",
      "https://meridian.example.com/api/v1/auth/saml/1/acs",
      "https://idp.example.com/sso");

  // Verify XML contains required elements
  EXPECT_NE(sXml.find("<samlp:AuthnRequest"), std::string::npos);
  EXPECT_NE(sXml.find("AssertionConsumerServiceURL="), std::string::npos);
  EXPECT_NE(sXml.find("<saml:Issuer>"), std::string::npos);
  EXPECT_NE(sXml.find("https://meridian.example.com"), std::string::npos);
  EXPECT_NE(sXml.find("ID=\"_"), std::string::npos);
  EXPECT_NE(sXml.find("Version=\"2.0\""), std::string::npos);
}

TEST_F(SamlServiceTest, BuildRedirectUrl) {
  std::string sAuthnRequest = "<samlp:AuthnRequest>test</samlp:AuthnRequest>";
  std::string sUrl = _upService->buildRedirectUrl(
      "https://idp.example.com/sso",
      sAuthnRequest,
      "relay-state-123");

  EXPECT_NE(sUrl.find("SAMLRequest="), std::string::npos);
  EXPECT_NE(sUrl.find("RelayState=relay-state-123"), std::string::npos);
  EXPECT_NE(sUrl.find("https://idp.example.com/sso"), std::string::npos);
}

TEST_F(SamlServiceTest, StoreAndRetrieveSamlState) {
  SamlAuthState saState;
  saState.iIdpId = 7;
  saState.sRequestId = "_abc123";
  saState.bIsTestMode = true;
  saState.tpCreatedAt = std::chrono::system_clock::now();

  _upService->storeAuthState("relay-key", saState);

  // First consume should succeed
  auto oResult = _upService->consumeAuthState("relay-key");
  ASSERT_TRUE(oResult.has_value());
  EXPECT_EQ(oResult->iIdpId, 7);
  EXPECT_EQ(oResult->sRequestId, "_abc123");
  EXPECT_TRUE(oResult->bIsTestMode);

  // Second consume should return nullopt
  auto oResult2 = _upService->consumeAuthState("relay-key");
  EXPECT_FALSE(oResult2.has_value());
}

// ── Task 7: Assertion validation tests ─────────────────────────────────────

TEST_F(SamlServiceTest, ValidateAssertionRejectsExpired) {
  // Build a minimal SAML response with NotOnOrAfter in the past
  std::string sSamlResponse =
      "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" "
      "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">"
      "<samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>"
      "</samlp:Status>"
      "<saml:Assertion ID=\"_assert1\">"
      "<saml:Conditions NotBefore=\"2020-01-01T00:00:00Z\" NotOnOrAfter=\"2020-01-01T01:00:00Z\">"
      "<saml:AudienceRestriction><saml:Audience>https://meridian.example.com</saml:Audience>"
      "</saml:AudienceRestriction></saml:Conditions>"
      "<saml:Subject><saml:NameID>user@example.com</saml:NameID>"
      "<saml:SubjectConfirmation><saml:SubjectConfirmationData InResponseTo=\"_req1\"/>"
      "</saml:SubjectConfirmation></saml:Subject>"
      "</saml:Assertion></samlp:Response>";

  // Base64 encode it (as IdP would send)
  std::string sEncoded = SamlService::base64Encode(sSamlResponse);

  EXPECT_THROW(
      _upService->validateAssertion(sEncoded, "", "https://meridian.example.com", "_req1"),
      dns::common::AuthenticationError);
}

TEST_F(SamlServiceTest, ValidateAssertionRejectsWrongAudience) {
  // Build a SAML response with valid timestamps but wrong audience
  auto tpNow = std::chrono::system_clock::now();
  auto tpFuture = tpNow + std::chrono::hours(1);

  std::string sNow = SamlService::formatIso8601(tpNow);
  std::string sFuture = SamlService::formatIso8601(tpFuture);

  std::string sSamlResponse =
      "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" "
      "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">"
      "<samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>"
      "</samlp:Status>"
      "<saml:Assertion ID=\"_assert2\">"
      "<saml:Conditions NotBefore=\"" + sNow + "\" NotOnOrAfter=\"" + sFuture + "\">"
      "<saml:AudienceRestriction><saml:Audience>https://wrong-audience.com</saml:Audience>"
      "</saml:AudienceRestriction></saml:Conditions>"
      "<saml:Subject><saml:NameID>user@example.com</saml:NameID>"
      "<saml:SubjectConfirmation><saml:SubjectConfirmationData InResponseTo=\"_req2\"/>"
      "</saml:SubjectConfirmation></saml:Subject>"
      "</saml:Assertion></samlp:Response>";

  std::string sEncoded = SamlService::base64Encode(sSamlResponse);

  EXPECT_THROW(
      _upService->validateAssertion(sEncoded, "", "https://meridian.example.com", "_req2"),
      dns::common::AuthenticationError);
}

TEST_F(SamlServiceTest, ExtractAttributes) {
  auto tpNow = std::chrono::system_clock::now();
  auto tpFuture = tpNow + std::chrono::hours(1);

  std::string sNow = SamlService::formatIso8601(tpNow);
  std::string sFuture = SamlService::formatIso8601(tpFuture);

  std::string sSamlResponse =
      "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" "
      "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">"
      "<samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>"
      "</samlp:Status>"
      "<saml:Assertion ID=\"_assert3\">"
      "<saml:Conditions NotBefore=\"" + sNow + "\" NotOnOrAfter=\"" + sFuture + "\">"
      "<saml:AudienceRestriction><saml:Audience>https://meridian.example.com</saml:Audience>"
      "</saml:AudienceRestriction></saml:Conditions>"
      "<saml:Subject><saml:NameID>user@example.com</saml:NameID>"
      "<saml:SubjectConfirmation><saml:SubjectConfirmationData InResponseTo=\"_req3\"/>"
      "</saml:SubjectConfirmation></saml:Subject>"
      "<saml:AttributeStatement>"
      "<saml:Attribute Name=\"email\"><saml:AttributeValue>user@example.com</saml:AttributeValue></saml:Attribute>"
      "<saml:Attribute Name=\"groups\">"
      "<saml:AttributeValue>dns-admins</saml:AttributeValue>"
      "<saml:AttributeValue>platform-team</saml:AttributeValue>"
      "</saml:Attribute>"
      "</saml:AttributeStatement>"
      "</saml:Assertion></samlp:Response>";

  std::string sEncoded = SamlService::base64Encode(sSamlResponse);

  // No certificate = skip signature verification (unit test)
  auto jResult = _upService->validateAssertion(
      sEncoded, "", "https://meridian.example.com", "_req3");

  EXPECT_EQ(jResult["name_id"], "user@example.com");
  ASSERT_TRUE(jResult.contains("attributes"));
  EXPECT_EQ(jResult["attributes"]["email"].size(), 1);
  EXPECT_EQ(jResult["attributes"]["email"][0], "user@example.com");
  EXPECT_EQ(jResult["attributes"]["groups"].size(), 2);
  EXPECT_EQ(jResult["attributes"]["groups"][0], "dns-admins");
  EXPECT_EQ(jResult["attributes"]["groups"][1], "platform-team");
}
