#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace dns::dal {
class GitRepoRepository;
class ZoneRepository;
class ViewRepository;
class RecordRepository;
}  // namespace dns::dal

namespace dns::core {
class VariableEngine;
}

namespace dns::gitops {

class GitRepoMirror;

/// Manages multiple GitRepoMirror instances, one per enabled git_repos row.
/// Class abbreviation: grmgr
class GitRepoManager {
 public:
  GitRepoManager(dns::dal::GitRepoRepository& grRepo,
                 dns::dal::ZoneRepository& zrRepo,
                 dns::dal::ViewRepository& vrRepo,
                 dns::dal::RecordRepository& rrRepo,
                 dns::core::VariableEngine& veEngine,
                 const std::string& sBasePath);
  ~GitRepoManager();

  /// Load all enabled repos from DB and initialize mirrors. Called at startup.
  void initialize();

  /// Reload a single repo mirror (add, update, or remove). Called after admin CRUD.
  void reloadRepo(int64_t iRepoId);

  /// Remove a repo mirror (called after admin deletes a repo).
  void removeRepo(int64_t iRepoId);

  /// Commit a zone snapshot to its assigned git repo.
  /// Looks up zone's git_repo_id, builds the snapshot, and commits.
  /// No-op if the zone has no git_repo_id assigned.
  void commitZoneSnapshot(int64_t iZoneId, const std::string& sActor);

  /// Pull (fetch) latest for all enabled mirrors.
  void pullAll();

  /// Pull for a single repo by ID.
  void pullRepo(int64_t iRepoId);

  /// Test connection for a repo: clone to temp dir, verify auth works.
  /// Returns empty string on success, error message on failure.
  std::string testConnection(int64_t iRepoId);

  /// Build the zone snapshot JSON (same format as GitOpsMirror::buildSnapshotJson).
  std::string buildSnapshotJson(int64_t iZoneId, const std::string& sActor) const;

 private:
  GitRepoMirror* findMirror(int64_t iRepoId);

  dns::dal::GitRepoRepository& _grRepo;
  dns::dal::ZoneRepository& _zrRepo;
  dns::dal::ViewRepository& _vrRepo;
  dns::dal::RecordRepository& _rrRepo;
  dns::core::VariableEngine& _veEngine;
  std::string _sBasePath;

  std::unordered_map<int64_t, std::unique_ptr<GitRepoMirror>> _mMirrors;
  std::mutex _mtx;
};

}  // namespace dns::gitops
