#include "common/Logger.hpp"

#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

namespace dns::common {

bool Logger::_bInitialized = false;

void Logger::init(const std::string& sLevel) {
  if (_bInitialized) {
    // Re-initialization: just update level
    spdlog::set_level(spdlog::level::from_str(sLevel));
    return;
  }

  auto spLogger = spdlog::stdout_color_mt("dns");
  spLogger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%n] %v");

  auto level = spdlog::level::from_str(sLevel);
  spLogger->set_level(level);
  spdlog::set_default_logger(spLogger);

  _bInitialized = true;
  spLogger->info("Logger initialized at level '{}'", sLevel);
}

std::shared_ptr<spdlog::logger> Logger::get() {
  if (!_bInitialized) {
    init("info");
  }
  return spdlog::default_logger();
}

}  // namespace dns::common
