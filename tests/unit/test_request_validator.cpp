#include "api/RequestValidator.hpp"
#include <gtest/gtest.h>
using dns::api::RequestValidator;

TEST(RequestValidatorTest, StringLengthAcceptsWithinLimit) {
  EXPECT_NO_THROW(RequestValidator::validateStringLength("hello", "name", 253));
}
TEST(RequestValidatorTest, StringLengthRejectsOverLimit) {
  EXPECT_THROW(RequestValidator::validateStringLength(std::string(254, 'a'), "name", 253),
               dns::common::ValidationError);
}
TEST(RequestValidatorTest, StringLengthRejectsEmpty) {
  EXPECT_THROW(RequestValidator::validateStringLength("", "name", 253),
               dns::common::ValidationError);
}
TEST(RequestValidatorTest, RequiredAcceptsNonEmpty) {
  EXPECT_NO_THROW(RequestValidator::validateRequired("hello", "name"));
}
TEST(RequestValidatorTest, RequiredRejectsEmpty) {
  EXPECT_THROW(RequestValidator::validateRequired("", "name"),
               dns::common::ValidationError);
}
TEST(RequestValidatorTest, ZoneNameAcceptsValid) {
  EXPECT_NO_THROW(RequestValidator::validateZoneName("example.com"));
}
TEST(RequestValidatorTest, ZoneNameRejectsTooLong) {
  EXPECT_THROW(RequestValidator::validateZoneName(std::string(254, 'a')),
               dns::common::ValidationError);
}
TEST(RequestValidatorTest, RecordTypeAcceptsA) {
  EXPECT_NO_THROW(RequestValidator::validateRecordType("A"));
}
TEST(RequestValidatorTest, RecordTypeRejectsInvalid) {
  EXPECT_THROW(RequestValidator::validateRecordType("INVALID"),
               dns::common::ValidationError);
}
TEST(RequestValidatorTest, TtlAccepts300) {
  EXPECT_NO_THROW(RequestValidator::validateTtl(300));
}
TEST(RequestValidatorTest, TtlRejectsZero) {
  EXPECT_THROW(RequestValidator::validateTtl(0), dns::common::ValidationError);
}
TEST(RequestValidatorTest, TtlRejectsTooLarge) {
  EXPECT_THROW(RequestValidator::validateTtl(604801), dns::common::ValidationError);
}
TEST(RequestValidatorTest, VariableNameAcceptsValid) {
  EXPECT_NO_THROW(RequestValidator::validateVariableName("LB_VIP"));
}
TEST(RequestValidatorTest, VariableNameRejectsInvalidChars) {
  EXPECT_THROW(RequestValidator::validateVariableName("invalid name!"),
               dns::common::ValidationError);
}
TEST(RequestValidatorTest, ProviderTypeAcceptsPowerdns) {
  EXPECT_NO_THROW(RequestValidator::validateProviderType("powerdns"));
}
TEST(RequestValidatorTest, ProviderTypeRejectsInvalid) {
  EXPECT_THROW(RequestValidator::validateProviderType("invalid"),
               dns::common::ValidationError);
}
TEST(RequestValidatorTest, ApiKeyDescriptionAcceptsEmpty) {
  EXPECT_NO_THROW(RequestValidator::validateApiKeyDescription(""));
}
TEST(RequestValidatorTest, ApiKeyDescriptionRejectsTooLong) {
  EXPECT_THROW(RequestValidator::validateApiKeyDescription(std::string(513, 'a')),
               dns::common::ValidationError);
}
