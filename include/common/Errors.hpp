#pragma once

#include <stdexcept>
#include <string>

namespace dns::common {

/// Base error for all application-level exceptions.
/// Class abbreviation: N/A (use derived types)
struct AppError : public std::runtime_error {
  int _iHttpStatus;
  std::string _sErrorCode;

  explicit AppError(int iHttpStatus, std::string sCode, std::string sMsg);
};

struct ValidationError : AppError {
  explicit ValidationError(std::string sCode, std::string sMsg);
};

struct AuthenticationError : AppError {
  explicit AuthenticationError(std::string sCode, std::string sMsg);
};

struct AuthorizationError : AppError {
  explicit AuthorizationError(std::string sCode, std::string sMsg);
};

struct NotFoundError : AppError {
  explicit NotFoundError(std::string sCode, std::string sMsg);
};

struct ConflictError : AppError {
  explicit ConflictError(std::string sCode, std::string sMsg);
};

struct ProviderError : AppError {
  explicit ProviderError(std::string sCode, std::string sMsg);
};

struct UnresolvedVariableError : AppError {
  explicit UnresolvedVariableError(std::string sCode, std::string sMsg);
};

struct DeploymentLockedError : AppError {
  explicit DeploymentLockedError(std::string sCode, std::string sMsg);
};

struct GitMirrorError : AppError {
  explicit GitMirrorError(std::string sCode, std::string sMsg);
};

}  // namespace dns::common
