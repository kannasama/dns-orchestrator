#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>

#include "common/Types.hpp"

namespace dns::dal {
class AuditRepository;
class DeploymentRepository;
class ProviderRepository;
class RecordRepository;
class ViewRepository;
class ZoneRepository;
}  // namespace dns::dal

namespace dns::gitops {
class GitRepoManager;
}

namespace dns::core {

class DiffEngine;
class VariableEngine;

/// Accepts a PreviewResult and executes the diff against the provider.
/// Class abbreviation: dep
class DeploymentEngine {
 public:
  DeploymentEngine(DiffEngine& deEngine,
                   VariableEngine& veEngine,
                   dns::dal::ZoneRepository& zrRepo,
                   dns::dal::ViewRepository& vrRepo,
                   dns::dal::RecordRepository& rrRepo,
                   dns::dal::ProviderRepository& prRepo,
                   dns::dal::DeploymentRepository& drRepo,
                   dns::dal::AuditRepository& arRepo,
                   dns::gitops::GitRepoManager* pGitRepoManager,
                   int iRetentionCount);
  ~DeploymentEngine();

  /// Execute the full push pipeline for a zone.
  /// Throws DeploymentLockedError if the zone is already being deployed.
  /// Throws ProviderError on provider failure.
  void push(int64_t iZoneId,
            const std::vector<common::DriftAction>& vDriftActions,
            int64_t iActorUserId, const std::string& sActor);

 private:
  /// Build the deployment snapshot JSON from current records.
  nlohmann::json buildSnapshot(int64_t iZoneId, const std::string& sActor) const;

  /// Get or create a per-zone mutex.
  std::mutex& zoneMutex(int64_t iZoneId);

  DiffEngine& _deEngine;
  VariableEngine& _veEngine;
  dns::dal::ZoneRepository& _zrRepo;
  dns::dal::ViewRepository& _vrRepo;
  dns::dal::RecordRepository& _rrRepo;
  dns::dal::ProviderRepository& _prRepo;
  dns::dal::DeploymentRepository& _drRepo;
  dns::dal::AuditRepository& _arRepo;
  dns::gitops::GitRepoManager* _pGitRepoManager;
  int _iRetentionCount;

  std::unordered_map<int64_t, std::unique_ptr<std::mutex>> _mZoneMutexes;
  std::mutex _mtxMap;
};

}  // namespace dns::core
