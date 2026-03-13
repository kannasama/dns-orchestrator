#include "security/OidcService.hpp"

#include "common/Errors.hpp"

#include <gtest/gtest.h>

#include <string>

using dns::security::OidcService;

// ── Task 4: Discovery & PKCE tests ────────────────────────────────────────

TEST(OidcServiceTest, GeneratePkceChallenge) {
  auto [sVerifier, sChallenge] = OidcService::generatePkce();

  // Verifier should be ~43 chars (32 bytes base64url)
  EXPECT_GE(sVerifier.size(), 40u);
  EXPECT_LE(sVerifier.size(), 50u);

  // Challenge should be ~43 chars (SHA-256 of verifier, base64url)
  EXPECT_GE(sChallenge.size(), 40u);
  EXPECT_LE(sChallenge.size(), 50u);

  // They must differ
  EXPECT_NE(sVerifier, sChallenge);
}

TEST(OidcServiceTest, GenerateState) {
  auto sState1 = OidcService::generateState();
  auto sState2 = OidcService::generateState();

  // Each state should be >= 20 chars
  EXPECT_GE(sState1.size(), 20u);
  EXPECT_GE(sState2.size(), 20u);

  // Two calls should produce different values
  EXPECT_NE(sState1, sState2);
}

TEST(OidcServiceTest, StoreAndRetrieveAuthState) {
  OidcService osService;

  dns::security::OidcAuthState oaState;
  oaState.sCodeVerifier = "test-verifier";
  oaState.iIdpId = 42;
  oaState.bIsTestMode = true;
  oaState.tpCreatedAt = std::chrono::system_clock::now();

  osService.storeAuthState("test-state-key", oaState);

  // First consume should succeed
  auto oResult = osService.consumeAuthState("test-state-key");
  ASSERT_TRUE(oResult.has_value());
  EXPECT_EQ(oResult->sCodeVerifier, "test-verifier");
  EXPECT_EQ(oResult->iIdpId, 42);
  EXPECT_TRUE(oResult->bIsTestMode);

  // Second consume should return nullopt (consumed)
  auto oResult2 = osService.consumeAuthState("test-state-key");
  EXPECT_FALSE(oResult2.has_value());
}

TEST(OidcServiceTest, BuildAuthorizationUrl) {
  std::string sUrl = OidcService::buildAuthorizationUrl(
      "https://idp.example.com/authorize",
      "my-client-id",
      "http://localhost:8080/callback",
      "openid email profile",
      "random-state-value",
      "code-challenge-value");

  EXPECT_NE(sUrl.find("response_type=code"), std::string::npos);
  EXPECT_NE(sUrl.find("client_id=my-client-id"), std::string::npos);
  EXPECT_NE(sUrl.find("state=random-state-value"), std::string::npos);
  EXPECT_NE(sUrl.find("code_challenge=code-challenge-value"), std::string::npos);
  EXPECT_NE(sUrl.find("code_challenge_method=S256"), std::string::npos);
  EXPECT_NE(sUrl.find("scope=openid"), std::string::npos);
}

// ── Task 5: Token validation tests ─────────────────────────────────────────

TEST(OidcServiceTest, ValidateIdTokenRejectsExpiredToken) {
  OidcService osService;

  // Build a minimal JWT with exp in the past (no signature — testing claim validation)
  auto iNow = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();

  nlohmann::json jPayload = {
      {"iss", "https://idp.example.com"},
      {"aud", "my-client-id"},
      {"sub", "user123"},
      {"exp", iNow - 3600},  // expired 1 hour ago
      {"iat", iNow - 7200},
  };

  EXPECT_THROW(
      osService.validateIdTokenClaims(jPayload, "https://idp.example.com", "my-client-id"),
      dns::common::AuthenticationError);
}

TEST(OidcServiceTest, ValidateIdTokenRejectsWrongIssuer) {
  OidcService osService;

  auto iNow = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();

  nlohmann::json jPayload = {
      {"iss", "https://wrong-issuer.com"},
      {"aud", "my-client-id"},
      {"sub", "user123"},
      {"exp", iNow + 3600},
      {"iat", iNow},
  };

  EXPECT_THROW(
      osService.validateIdTokenClaims(jPayload, "https://idp.example.com", "my-client-id"),
      dns::common::AuthenticationError);
}

TEST(OidcServiceTest, ValidateIdTokenRejectsWrongAudience) {
  OidcService osService;

  auto iNow = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();

  nlohmann::json jPayload = {
      {"iss", "https://idp.example.com"},
      {"aud", "wrong-client-id"},
      {"sub", "user123"},
      {"exp", iNow + 3600},
      {"iat", iNow},
  };

  EXPECT_THROW(
      osService.validateIdTokenClaims(jPayload, "https://idp.example.com", "my-client-id"),
      dns::common::AuthenticationError);
}

TEST(OidcServiceTest, ValidateIdTokenAcceptsValidClaims) {
  OidcService osService;

  auto iNow = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();

  nlohmann::json jPayload = {
      {"iss", "https://idp.example.com"},
      {"aud", "my-client-id"},
      {"sub", "user123"},
      {"exp", iNow + 3600},
      {"iat", iNow},
  };

  // Should not throw
  EXPECT_NO_THROW(
      osService.validateIdTokenClaims(jPayload, "https://idp.example.com", "my-client-id"));
}
