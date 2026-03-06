#include "api/StaticFileHandler.hpp"

#include <filesystem>
#include <fstream>
#include <sstream>

#include <spdlog/spdlog.h>

namespace fs = std::filesystem;

namespace dns::api {

StaticFileHandler::StaticFileHandler(const std::string& sUiDir)
    : _sUiDir(sUiDir) {}

void StaticFileHandler::registerRoutes(crow::SimpleApp& app) {
  if (_sUiDir.empty() || !fs::is_directory(_sUiDir)) {
    spdlog::info("UI directory not configured or not found — static serving disabled");
    return;
  }

  spdlog::info("Serving static UI files from {}", _sUiDir);

  // Crow catchall route — serves static files or falls back to index.html for SPA routing
  CROW_CATCHALL_ROUTE(app)
  ([this](const crow::request& req) {
    std::string sPath = req.url;

    // Skip API routes
    if (sPath.rfind("/api/", 0) == 0) {
      return crow::response(404, "Not found");
    }

    // Remove leading slash and try to serve the file
    if (!sPath.empty() && sPath[0] == '/') {
      sPath = sPath.substr(1);
    }

    // Try the exact file path
    std::string sFullPath = _sUiDir + "/" + sPath;
    if (!sPath.empty() && fs::is_regular_file(sFullPath)) {
      auto sContent = readFile(sFullPath);
      auto res = crow::response(200, sContent);
      res.set_header("Content-Type", mimeType(sFullPath));
      return res;
    }

    // SPA fallback: serve index.html
    std::string sIndexPath = _sUiDir + "/index.html";
    if (fs::is_regular_file(sIndexPath)) {
      auto sContent = readFile(sIndexPath);
      auto res = crow::response(200, sContent);
      res.set_header("Content-Type", "text/html; charset=utf-8");
      return res;
    }

    return crow::response(404, "Not found");
  });
}

std::string StaticFileHandler::readFile(const std::string& sPath) {
  std::ifstream ifs(sPath, std::ios::binary);
  if (!ifs) return {};
  std::ostringstream oss;
  oss << ifs.rdbuf();
  return oss.str();
}

std::string StaticFileHandler::mimeType(const std::string& sPath) {
  auto sExt = fs::path(sPath).extension().string();
  if (sExt == ".html") return "text/html; charset=utf-8";
  if (sExt == ".css") return "text/css; charset=utf-8";
  if (sExt == ".js") return "application/javascript; charset=utf-8";
  if (sExt == ".json") return "application/json; charset=utf-8";
  if (sExt == ".svg") return "image/svg+xml";
  if (sExt == ".png") return "image/png";
  if (sExt == ".ico") return "image/x-icon";
  if (sExt == ".woff") return "font/woff";
  if (sExt == ".woff2") return "font/woff2";
  if (sExt == ".ttf") return "font/ttf";
  return "application/octet-stream";
}

}  // namespace dns::api
