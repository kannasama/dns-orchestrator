#pragma once

#include <cstdint>
#include <string>

namespace dns::core {

/// Accepts a PreviewResult and executes the diff against the provider.
/// Class abbreviation: dep
class DeploymentEngine {
 public:
  DeploymentEngine();
  ~DeploymentEngine();

  void push(int64_t iZoneId, bool bPurgeDrift, const std::string& sActor);
};

}  // namespace dns::core
