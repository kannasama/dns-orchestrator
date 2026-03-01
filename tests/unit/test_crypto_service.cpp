#include "security/CryptoService.hpp"

#include <gtest/gtest.h>

#include <set>
#include <string>

using dns::security::CryptoService;

// A valid 64-char hex key for testing (32 bytes)
static const std::string kTestKey =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

TEST(CryptoServiceTest, EncryptDecryptRoundtrip) {
  CryptoService cs(kTestKey);
  const std::string sPlaintext = "Hello, DNS Orchestrator!";

  std::string sCiphertext = cs.encrypt(sPlaintext);
  EXPECT_NE(sCiphertext, sPlaintext);
  EXPECT_NE(sCiphertext.find(':'), std::string::npos);  // iv:data format

  std::string sDecrypted = cs.decrypt(sCiphertext);
  EXPECT_EQ(sDecrypted, sPlaintext);
}

TEST(CryptoServiceTest, EncryptProducesDifferentIVsPerCall) {
  CryptoService cs(kTestKey);
  const std::string sPlaintext = "same input";

  std::string sCipher1 = cs.encrypt(sPlaintext);
  std::string sCipher2 = cs.encrypt(sPlaintext);

  // Different IVs should produce different ciphertexts
  EXPECT_NE(sCipher1, sCipher2);

  // Both should decrypt to the same plaintext
  EXPECT_EQ(cs.decrypt(sCipher1), sPlaintext);
  EXPECT_EQ(cs.decrypt(sCipher2), sPlaintext);
}

TEST(CryptoServiceTest, DecryptWithWrongKeyFails) {
  CryptoService cs1(kTestKey);
  CryptoService cs2("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");

  std::string sCiphertext = cs1.encrypt("secret data");
  EXPECT_THROW(cs2.decrypt(sCiphertext), std::exception);
}

TEST(CryptoServiceTest, EmptyPlaintextRoundtrip) {
  CryptoService cs(kTestKey);
  std::string sCiphertext = cs.encrypt("");
  EXPECT_EQ(cs.decrypt(sCiphertext), "");
}

TEST(CryptoServiceTest, GenerateApiKeyIs43Chars) {
  std::string sKey = CryptoService::generateApiKey();
  EXPECT_EQ(sKey.size(), 43u);

  // Should be base64url: only [A-Za-z0-9_-]
  for (char c : sKey) {
    EXPECT_TRUE(std::isalnum(c) || c == '-' || c == '_')
        << "Unexpected character in API key: " << c;
  }
}

TEST(CryptoServiceTest, GenerateApiKeyIsUnique) {
  std::set<std::string> stKeys;
  for (int i = 0; i < 100; ++i) {
    stKeys.insert(CryptoService::generateApiKey());
  }
  // All 100 keys should be unique
  EXPECT_EQ(stKeys.size(), 100u);
}

TEST(CryptoServiceTest, HashApiKeyIs128CharHex) {
  std::string sHash = CryptoService::hashApiKey("test-key-12345");
  EXPECT_EQ(sHash.size(), 128u);

  // Should be hex: only [0-9a-f]
  for (char c : sHash) {
    EXPECT_TRUE((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
        << "Unexpected character in hash: " << c;
  }
}

TEST(CryptoServiceTest, HashApiKeyIsDeterministic) {
  std::string sHash1 = CryptoService::hashApiKey("same-key");
  std::string sHash2 = CryptoService::hashApiKey("same-key");
  EXPECT_EQ(sHash1, sHash2);
}

TEST(CryptoServiceTest, HashApiKeyDifferentInputsDifferentHashes) {
  std::string sHash1 = CryptoService::hashApiKey("key-one");
  std::string sHash2 = CryptoService::hashApiKey("key-two");
  EXPECT_NE(sHash1, sHash2);
}

TEST(CryptoServiceTest, RejectsInvalidMasterKeyLength) {
  EXPECT_THROW(CryptoService("too-short"), std::runtime_error);
  EXPECT_THROW(CryptoService(""), std::runtime_error);
}

// ── SHA-256 tests ──────────────────────────────────────────────────────────

TEST(CryptoServiceTest, Sha256HexReturns64CharHexString) {
  std::string sHash = CryptoService::sha256Hex("hello world");
  EXPECT_EQ(sHash.size(), 64u);
  for (char c : sHash) {
    EXPECT_TRUE((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
        << "Unexpected character in SHA-256 hash: " << c;
  }
}

TEST(CryptoServiceTest, Sha256HexIsDeterministic) {
  EXPECT_EQ(CryptoService::sha256Hex("test"), CryptoService::sha256Hex("test"));
}

TEST(CryptoServiceTest, Sha256HexDifferentInputsDiffer) {
  EXPECT_NE(CryptoService::sha256Hex("one"), CryptoService::sha256Hex("two"));
}

TEST(CryptoServiceTest, Sha256HexKnownVector) {
  // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  EXPECT_EQ(CryptoService::sha256Hex(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

// ── Argon2id tests ─────────────────────────────────────────────────────────

TEST(CryptoServiceTest, HashPasswordReturnsPHCString) {
  std::string sHash = CryptoService::hashPassword("MyP@ssw0rd!");
  // PHC format: $argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>
  EXPECT_EQ(sHash.substr(0, 10), "$argon2id$");
}

TEST(CryptoServiceTest, HashPasswordProducesUniqueSalts) {
  std::string sHash1 = CryptoService::hashPassword("same-password");
  std::string sHash2 = CryptoService::hashPassword("same-password");
  EXPECT_NE(sHash1, sHash2);  // different salts → different hashes
}

TEST(CryptoServiceTest, VerifyPasswordCorrect) {
  std::string sHash = CryptoService::hashPassword("correct-horse-battery-staple");
  EXPECT_TRUE(CryptoService::verifyPassword("correct-horse-battery-staple", sHash));
}

TEST(CryptoServiceTest, VerifyPasswordWrong) {
  std::string sHash = CryptoService::hashPassword("right-password");
  EXPECT_FALSE(CryptoService::verifyPassword("wrong-password", sHash));
}

TEST(CryptoServiceTest, VerifyPasswordEmptyPasswordWorks) {
  std::string sHash = CryptoService::hashPassword("");
  EXPECT_TRUE(CryptoService::verifyPassword("", sHash));
  EXPECT_FALSE(CryptoService::verifyPassword("not-empty", sHash));
}
