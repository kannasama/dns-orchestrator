#pragma once
#include <cstddef>
#include <string>
#include "common/Errors.hpp"

namespace dns::api {

/// Centralized input validation (ARCHITECTURE.md §4.6.5).
/// All methods throw ValidationError on failure.
/// Class abbreviation: rv
class RequestValidator {
 public:
  static void validateStringLength(const std::string& sValue,
                                   const std::string& sFieldName, size_t nMaxLength);
  static void validateRequired(const std::string& sValue, const std::string& sFieldName);
  static void validateZoneName(const std::string& sName);
  static void validateRecordName(const std::string& sName);
  static void validateRecordType(const std::string& sType);
  static void validateValueTemplate(const std::string& sValue);
  static void validateTtl(int iTtl);
  static void validateVariableName(const std::string& sName);
  static void validateVariableValue(const std::string& sValue);
  static void validateProviderName(const std::string& sName);
  static void validateProviderType(const std::string& sType);
  static void validateUsername(const std::string& sUsername);
  static void validatePassword(const std::string& sPassword);
  static void validateApiKeyDescription(const std::string& sDescription);
  static void validateGroupName(const std::string& sName);
  static void validateGitRepoName(const std::string& sName);
  static void validateGitRemoteUrl(const std::string& sUrl);
  static void validateGitAuthType(const std::string& sAuthType);
  static void validateGitBranch(const std::string& sBranch);
};

}  // namespace dns::api
