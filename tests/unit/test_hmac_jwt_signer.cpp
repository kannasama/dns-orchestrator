#include "security/HmacJwtSigner.hpp"

#include "common/Errors.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <string>

using dns::security::HmacJwtSigner;
using dns::common::AuthenticationError;

static const std::string kTestSecret = "super-secret-jwt-key-for-testing";

TEST(HmacJwtSignerTest, SignVerifyRoundtrip) {
  HmacJwtSigner signer(kTestSecret);

  auto iNow = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();

  nlohmann::json jPayload = {
      {"sub", "42"},
      {"username", "alice"},
      {"role", "admin"},
      {"auth_method", "local"},
      {"iat", iNow},
      {"exp", iNow + 3600}};

  std::string sToken = signer.sign(jPayload);

  // Token should have 3 parts separated by dots
  int iDots = 0;
  for (char c : sToken) {
    if (c == '.') ++iDots;
  }
  EXPECT_EQ(iDots, 2);

  // Verify should return the same payload
  nlohmann::json jVerified = signer.verify(sToken);
  EXPECT_EQ(jVerified["sub"], "42");
  EXPECT_EQ(jVerified["username"], "alice");
  EXPECT_EQ(jVerified["role"], "admin");
  EXPECT_EQ(jVerified["auth_method"], "local");
}

TEST(HmacJwtSignerTest, ExpiredTokenThrowsAuthenticationError) {
  HmacJwtSigner signer(kTestSecret);

  auto iNow = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();

  nlohmann::json jPayload = {
      {"sub", "1"},
      {"exp", iNow - 100}};  // expired 100 seconds ago

  std::string sToken = signer.sign(jPayload);

  EXPECT_THROW({
    try {
      signer.verify(sToken);
    } catch (const AuthenticationError& e) {
      EXPECT_EQ(e._sErrorCode, "token_expired");
      throw;
    }
  }, AuthenticationError);
}

TEST(HmacJwtSignerTest, TamperedTokenThrows) {
  HmacJwtSigner signer(kTestSecret);

  auto iNow = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();

  nlohmann::json jPayload = {{"sub", "1"}, {"exp", iNow + 3600}};
  std::string sToken = signer.sign(jPayload);

  // Tamper with the payload (change a character)
  auto nFirstDot = sToken.find('.');
  auto nSecondDot = sToken.find('.', nFirstDot + 1);
  std::string sTampered = sToken;
  // Change a character in the payload section
  if (nSecondDot > nFirstDot + 2) {
    sTampered[nFirstDot + 1] = (sTampered[nFirstDot + 1] == 'A') ? 'B' : 'A';
  }

  EXPECT_THROW(signer.verify(sTampered), AuthenticationError);
}

TEST(HmacJwtSignerTest, WrongSecretRejects) {
  HmacJwtSigner signer1(kTestSecret);
  HmacJwtSigner signer2("different-secret-key");

  auto iNow = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();

  nlohmann::json jPayload = {{"sub", "1"}, {"exp", iNow + 3600}};
  std::string sToken = signer1.sign(jPayload);

  EXPECT_THROW(signer2.verify(sToken), AuthenticationError);
}

TEST(HmacJwtSignerTest, MalformedTokenThrows) {
  HmacJwtSigner signer(kTestSecret);

  EXPECT_THROW(signer.verify("not-a-jwt"), AuthenticationError);
  EXPECT_THROW(signer.verify("only.one-dot"), AuthenticationError);
  EXPECT_THROW(signer.verify("too.many.dots.here"), AuthenticationError);
}

TEST(HmacJwtSignerTest, PayloadFieldsPreserved) {
  HmacJwtSigner signer(kTestSecret);

  auto iNow = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();

  nlohmann::json jPayload = {
      {"sub", "99"},
      {"username", "bob"},
      {"role", "operator"},
      {"auth_method", "oidc"},
      {"iat", iNow},
      {"exp", iNow + 7200},
      {"custom_field", "preserved"}};

  std::string sToken = signer.sign(jPayload);
  nlohmann::json jVerified = signer.verify(sToken);

  EXPECT_EQ(jVerified["sub"], "99");
  EXPECT_EQ(jVerified["username"], "bob");
  EXPECT_EQ(jVerified["role"], "operator");
  EXPECT_EQ(jVerified["auth_method"], "oidc");
  EXPECT_EQ(jVerified["iat"], iNow);
  EXPECT_EQ(jVerified["exp"], iNow + 7200);
  EXPECT_EQ(jVerified["custom_field"], "preserved");
}
