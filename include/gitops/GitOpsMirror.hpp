#pragma once

#include <cstdint>
#include <string>

namespace dns::gitops {

/// Maintains a local bare-clone and pushes zone snapshots on deployment.
/// Class abbreviation: gm
class GitOpsMirror {
 public:
  GitOpsMirror();
  ~GitOpsMirror();

  void initialize(const std::string& sRemoteUrl, const std::string& sLocalPath);
  void commit(int64_t iZoneId, const std::string& sActorIdentity);
  void pull();

 private:
  void writeZoneSnapshot(int64_t iZoneId);
  void gitAddCommitPush(const std::string& sMessage);
};

}  // namespace dns::gitops
