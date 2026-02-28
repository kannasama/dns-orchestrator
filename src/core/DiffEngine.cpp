#include "core/DiffEngine.hpp"

#include <stdexcept>

namespace dns::core {

DiffEngine::DiffEngine() = default;
DiffEngine::~DiffEngine() = default;

common::PreviewResult DiffEngine::preview(int64_t /*iZoneId*/) {
  throw std::runtime_error{"not implemented"};
}

}  // namespace dns::core
