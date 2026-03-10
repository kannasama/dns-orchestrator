#include "api/RouteHelpers.hpp"

namespace dns::api {

namespace {
void applySecurityHeaders(crow::response& resp) {
  resp.set_header("X-Content-Type-Options", "nosniff");
  resp.set_header("X-Frame-Options", "DENY");
  resp.set_header("Referrer-Policy", "strict-origin-when-cross-origin");
  resp.set_header("Content-Security-Policy", "default-src 'self'");
}
}  // namespace

common::RequestContext authenticate(const AuthMiddleware& amMiddleware,
                                    const crow::request& req) {
  return amMiddleware.authenticate(req.get_header_value("Authorization"),
                                   req.get_header_value("X-API-Key"));
}

void requireRole(const common::RequestContext& rcCtx, const std::string& sMinRole) {
  if (sMinRole == "admin" && rcCtx.sRole != "admin") {
    throw common::AuthorizationError("INSUFFICIENT_ROLE", "Admin role required");
  }
  if (sMinRole == "operator" && rcCtx.sRole == "viewer") {
    throw common::AuthorizationError("INSUFFICIENT_ROLE",
                                     "Operator or admin role required");
  }
}

void requirePermission(const common::RequestContext& rcCtx, std::string_view svPermission) {
  if (rcCtx.vPermissions.count(std::string(svPermission)) == 0) {
    throw common::AuthorizationError(
        "INSUFFICIENT_PERMISSION",
        "Required permission: " + std::string(svPermission));
  }
}

crow::response jsonResponse(int iStatus, const nlohmann::json& j) {
  crow::response resp(iStatus, j.dump(2));
  resp.set_header("Content-Type", "application/json");
  applySecurityHeaders(resp);
  return resp;
}

crow::response errorResponse(const common::AppError& e) {
  nlohmann::json jErr = {{"error", e._sErrorCode}, {"message", e.what()}};
  crow::response resp(e._iHttpStatus, jErr.dump(2));
  resp.set_header("Content-Type", "application/json");
  applySecurityHeaders(resp);
  return resp;
}

crow::response invalidJsonResponse() {
  nlohmann::json jErr = {{"error", "invalid_json"},
                         {"message", "Invalid JSON body"}};
  crow::response resp(400, jErr.dump(2));
  resp.set_header("Content-Type", "application/json");
  applySecurityHeaders(resp);
  return resp;
}

}  // namespace dns::api
