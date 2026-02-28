#pragma once

#include <memory>
#include <string>

namespace spdlog {
class logger;
}

namespace dns::common {

/// Thin wrapper over spdlog for structured logging.
/// Class abbreviation: N/A (static interface)
class Logger {
 public:
  /// Initialize the global logger with the given level string.
  static void init(const std::string& sLevel);

  /// Get the shared spdlog logger instance.
  static std::shared_ptr<spdlog::logger> get();
};

}  // namespace dns::common
