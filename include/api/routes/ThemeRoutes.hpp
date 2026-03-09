#pragma once

#include <crow.h>
#include <string>

namespace dns::api::routes {

/// Handler for GET /api/v1/themes (no auth required)
/// Reads custom theme preset JSON files from /var/lib/meridian-dns/custom_themes/.
class ThemeRoutes {
 public:
  ThemeRoutes();
  ~ThemeRoutes();

  /// Register theme route on the Crow app.
  void registerRoutes(crow::SimpleApp& app);

 private:
  static constexpr const char* kCustomThemesDir = "/var/lib/meridian-dns/custom_themes";
};

}  // namespace dns::api::routes
