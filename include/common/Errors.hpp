#pragma once

#include <stdexcept>
#include <string>
#include <utility>

namespace dns::common {

/// Base error for all application-level exceptions.
/// Carries HTTP status code and machine-readable error code slug.
struct AppError : public std::runtime_error {
  int _iHttpStatus;
  std::string _sErrorCode;

  explicit AppError(int iHttpStatus, std::string sCode, std::string sMsg)
      : std::runtime_error(std::move(sMsg)),
        _iHttpStatus(iHttpStatus),
        _sErrorCode(std::move(sCode)) {}
};

/// 400 Bad Request — input validation failures.
struct ValidationError : AppError {
  explicit ValidationError(std::string sCode, std::string sMsg)
      : AppError(400, std::move(sCode), std::move(sMsg)) {}
};

/// 401 Unauthorized — authentication failures.
struct AuthenticationError : AppError {
  explicit AuthenticationError(std::string sCode, std::string sMsg)
      : AppError(401, std::move(sCode), std::move(sMsg)) {}
};

/// 403 Forbidden — authorization failures (valid identity, insufficient role).
struct AuthorizationError : AppError {
  explicit AuthorizationError(std::string sCode, std::string sMsg)
      : AppError(403, std::move(sCode), std::move(sMsg)) {}
};

/// 404 Not Found — requested entity does not exist.
struct NotFoundError : AppError {
  explicit NotFoundError(std::string sCode, std::string sMsg)
      : AppError(404, std::move(sCode), std::move(sMsg)) {}
};

/// 409 Conflict — state conflict (e.g., duplicate name).
struct ConflictError : AppError {
  explicit ConflictError(std::string sCode, std::string sMsg)
      : AppError(409, std::move(sCode), std::move(sMsg)) {}
};

/// 502 Bad Gateway — upstream DNS provider error.
struct ProviderError : AppError {
  explicit ProviderError(std::string sCode, std::string sMsg)
      : AppError(502, std::move(sCode), std::move(sMsg)) {}
};

/// 422 Unprocessable Entity — variable expansion failure.
struct UnresolvedVariableError : AppError {
  explicit UnresolvedVariableError(std::string sCode, std::string sMsg)
      : AppError(422, std::move(sCode), std::move(sMsg)) {}
};

/// 409 Conflict — zone is currently being deployed.
struct DeploymentLockedError : AppError {
  explicit DeploymentLockedError(std::string sCode, std::string sMsg)
      : AppError(409, std::move(sCode), std::move(sMsg)) {}
};

/// 500 Internal Server Error — GitOps mirror failure (non-fatal: logged, push still succeeds).
struct GitMirrorError : AppError {
  explicit GitMirrorError(std::string sCode, std::string sMsg)
      : AppError(500, std::move(sCode), std::move(sMsg)) {}
};

}  // namespace dns::common
