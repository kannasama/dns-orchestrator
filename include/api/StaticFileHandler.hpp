#pragma once

#include <crow.h>
#include <string>

namespace dns::api {

/// Serves static files from the UI build directory.
/// Falls back to index.html for SPA history mode routing.
/// Class abbreviation: sfh
class StaticFileHandler {
 public:
  /// @param sUiDir Absolute path to the directory containing built UI assets.
  explicit StaticFileHandler(const std::string& sUiDir);

  /// Register catch-all route on the Crow app.
  void registerRoutes(crow::SimpleApp& app);

 private:
  std::string _sUiDir;

  /// Read a file from disk and return its contents (empty string on failure).
  static std::string readFile(const std::string& sPath);

  /// Guess MIME type from file extension.
  static std::string mimeType(const std::string& sPath);
};

}  // namespace dns::api
