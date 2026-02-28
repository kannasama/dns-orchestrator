#pragma once

#include <cstdint>

#include "common/Types.hpp"

namespace dns::core {

/// Computes three-way diff between staged records and live provider state.
/// Class abbreviation: de
class DiffEngine {
 public:
  DiffEngine();
  ~DiffEngine();

  common::PreviewResult preview(int64_t iZoneId);
};

}  // namespace dns::core
