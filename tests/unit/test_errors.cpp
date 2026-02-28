#include "common/Errors.hpp"

#include <gtest/gtest.h>

using namespace dns::common;

TEST(ErrorsTest, AppErrorCarriesStatusAndCode) {
  AppError err(500, "internal_error", "Something went wrong");
  EXPECT_EQ(err._iHttpStatus, 500);
  EXPECT_EQ(err._sErrorCode, "internal_error");
  EXPECT_STREQ(err.what(), "Something went wrong");
}

TEST(ErrorsTest, ValidationErrorIs400) {
  ValidationError err("invalid_input", "Name too long");
  EXPECT_EQ(err._iHttpStatus, 400);
  EXPECT_EQ(err._sErrorCode, "invalid_input");
}

TEST(ErrorsTest, AuthenticationErrorIs401) {
  AuthenticationError err("token_expired", "JWT has expired");
  EXPECT_EQ(err._iHttpStatus, 401);
  EXPECT_EQ(err._sErrorCode, "token_expired");
}

TEST(ErrorsTest, AuthorizationErrorIs403) {
  AuthorizationError err("insufficient_role", "Admin required");
  EXPECT_EQ(err._iHttpStatus, 403);
  EXPECT_EQ(err._sErrorCode, "insufficient_role");
}

TEST(ErrorsTest, NotFoundErrorIs404) {
  NotFoundError err("zone_not_found", "Zone does not exist");
  EXPECT_EQ(err._iHttpStatus, 404);
  EXPECT_EQ(err._sErrorCode, "zone_not_found");
}

TEST(ErrorsTest, ConflictErrorIs409) {
  ConflictError err("duplicate_name", "Name already exists");
  EXPECT_EQ(err._iHttpStatus, 409);
  EXPECT_EQ(err._sErrorCode, "duplicate_name");
}

TEST(ErrorsTest, ProviderErrorIs502) {
  ProviderError err("provider_unreachable", "Connection timeout");
  EXPECT_EQ(err._iHttpStatus, 502);
  EXPECT_EQ(err._sErrorCode, "provider_unreachable");
}

TEST(ErrorsTest, UnresolvedVariableErrorIs422) {
  UnresolvedVariableError err("unresolved_variable", "Variable 'LB_VIP' not defined");
  EXPECT_EQ(err._iHttpStatus, 422);
  EXPECT_EQ(err._sErrorCode, "unresolved_variable");
}

TEST(ErrorsTest, DeploymentLockedErrorIs409) {
  DeploymentLockedError err("deployment_locked", "Zone 42 is being pushed");
  EXPECT_EQ(err._iHttpStatus, 409);
  EXPECT_EQ(err._sErrorCode, "deployment_locked");
}

TEST(ErrorsTest, GitMirrorErrorIs500) {
  GitMirrorError err("git_push_failed", "Remote rejected push");
  EXPECT_EQ(err._iHttpStatus, 500);
  EXPECT_EQ(err._sErrorCode, "git_push_failed");
}

TEST(ErrorsTest, PolymorphicCatchAsAppError) {
  // All derived types should be catchable as AppError&
  try {
    throw ValidationError("test", "test message");
  } catch (const AppError& err) {
    EXPECT_EQ(err._iHttpStatus, 400);
    EXPECT_EQ(err._sErrorCode, "test");
    EXPECT_STREQ(err.what(), "test message");
  }

  try {
    throw AuthenticationError("test", "auth fail");
  } catch (const AppError& err) {
    EXPECT_EQ(err._iHttpStatus, 401);
  }

  try {
    throw ProviderError("test", "provider fail");
  } catch (const AppError& err) {
    EXPECT_EQ(err._iHttpStatus, 502);
  }
}

TEST(ErrorsTest, CatchableAsStdRuntimeError) {
  try {
    throw NotFoundError("nf", "not found");
  } catch (const std::runtime_error& err) {
    EXPECT_STREQ(err.what(), "not found");
  }
}
