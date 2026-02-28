#include "core/VariableEngine.hpp"

#include <stdexcept>

namespace dns::core {

VariableEngine::VariableEngine() = default;
VariableEngine::~VariableEngine() = default;

std::string VariableEngine::expand(const std::string& /*sTmpl*/, int64_t /*iZoneId*/) const {
  throw std::runtime_error{"not implemented"};
}

bool VariableEngine::validate(const std::string& /*sTmpl*/, int64_t /*iZoneId*/) const {
  throw std::runtime_error{"not implemented"};
}

std::vector<std::string> VariableEngine::listDependencies(const std::string& /*sTmpl*/) const {
  throw std::runtime_error{"not implemented"};
}

}  // namespace dns::core
