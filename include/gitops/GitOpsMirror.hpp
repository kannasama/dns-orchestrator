#pragma once

#include <cstdint>
#include <mutex>
#include <string>

struct git_repository;

namespace dns::dal {
class RecordRepository;
class ViewRepository;
class ZoneRepository;
}  // namespace dns::dal

namespace dns::core {
class VariableEngine;
}

namespace dns::gitops {

/// Maintains a local bare-clone and pushes zone snapshots on deployment.
/// Class abbreviation: gm
class GitOpsMirror {
 public:
  GitOpsMirror(dns::dal::ZoneRepository& zrRepo,
               dns::dal::ViewRepository& vrRepo,
               dns::dal::RecordRepository& rrRepo,
               dns::core::VariableEngine& veEngine);
  ~GitOpsMirror();

  /// Clone or open existing repo. If remote URL is set, clone/fetch.
  void initialize(const std::string& sRemoteUrl, const std::string& sLocalPath);

  /// Write zone snapshot and commit+push to remote.
  /// Serialized globally via mutex. Non-fatal: logs errors but does not throw.
  void commit(int64_t iZoneId, const std::string& sActorIdentity);

  /// Fetch latest from remote (called at startup).
  void pull();

  /// Build zone snapshot JSON string (public for testing).
  std::string buildSnapshotJson(int64_t iZoneId, const std::string& sActor) const;

 private:
  void writeZoneSnapshot(int64_t iZoneId, const std::string& sActor);
  void gitAddCommitPush(const std::string& sMessage);

  dns::dal::ZoneRepository& _zrRepo;
  dns::dal::ViewRepository& _vrRepo;
  dns::dal::RecordRepository& _rrRepo;
  dns::core::VariableEngine& _veEngine;

  std::string _sLocalPath;
  std::string _sRemoteUrl;
  git_repository* _pRepo = nullptr;
  std::mutex _mtx;  // serializes all git operations
};

}  // namespace dns::gitops
