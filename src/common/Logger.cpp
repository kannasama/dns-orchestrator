#include "common/Logger.hpp"

#include <stdexcept>

namespace dns::common {

void Logger::init(const std::string& /*sLevel*/) {
  throw std::runtime_error{"not implemented"};
}

std::shared_ptr<spdlog::logger> Logger::get() {
  throw std::runtime_error{"not implemented"};
}

}  // namespace dns::common
