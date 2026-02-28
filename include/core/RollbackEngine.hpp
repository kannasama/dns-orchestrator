#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace dns::core {

/// Restores deployment snapshots into the desired state.
/// Class abbreviation: re
class RollbackEngine {
 public:
  RollbackEngine();
  ~RollbackEngine();

  void apply(int64_t iZoneId, int64_t iDeploymentId,
             const std::vector<int64_t>& vCherryPickIds,
             const std::string& sActor);
};

}  // namespace dns::core
