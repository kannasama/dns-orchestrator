#pragma once

#include <string>
#include <string_view>

#include <crow.h>
#include <nlohmann/json.hpp>

#include "api/AuthMiddleware.hpp"
#include "common/Errors.hpp"
#include "common/Types.hpp"

namespace dns::api {

/// Authenticate a Crow request via AuthMiddleware.
common::RequestContext authenticate(const AuthMiddleware& amMiddleware,
                                    const crow::request& req);

/// Enforce minimum role. Throws AuthorizationError if insufficient.
/// @deprecated Use requirePermission() instead.
void requireRole(const common::RequestContext& rcCtx, const std::string& sMinRole);

/// Enforce a specific permission. Throws AuthorizationError if the user
/// does not have the required permission in their RequestContext.
void requirePermission(const common::RequestContext& rcCtx, std::string_view svPermission);

/// Build a JSON response with Content-Type and security headers.
crow::response jsonResponse(int iStatus, const nlohmann::json& j);

/// Build an error response from an AppError with security headers.
crow::response errorResponse(const common::AppError& e);

/// Build an error response for invalid JSON parse failures.
crow::response invalidJsonResponse();

}  // namespace dns::api
