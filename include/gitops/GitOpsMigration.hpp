#pragma once

#include <string>

namespace dns::dal {
class GitRepoRepository;
class ZoneRepository;
}  // namespace dns::dal

namespace dns::gitops {

/// One-time migration from DNS_GIT_REMOTE_URL env var to git_repos table.
/// Called during startup after DB migrations.
class GitOpsMigration {
 public:
  /// Check if legacy env vars are set and no git_repos exist.
  /// If so, create a git_repos row and assign all zones to it.
  /// Returns true if migration was performed.
  static bool migrateIfNeeded(dns::dal::GitRepoRepository& grRepo,
                              dns::dal::ZoneRepository& zrRepo);
};

}  // namespace dns::gitops
