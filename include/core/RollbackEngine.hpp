#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace dns::dal {
class AuditRepository;
class DeploymentRepository;
class RecordRepository;
}  // namespace dns::dal

namespace dns::core {

/// Restores deployment snapshots into the desired state.
/// Class abbreviation: re
class RollbackEngine {
 public:
  RollbackEngine(dns::dal::DeploymentRepository& drRepo,
                 dns::dal::RecordRepository& rrRepo,
                 dns::dal::AuditRepository& arRepo);
  ~RollbackEngine();

  /// Restore a snapshot into the records table.
  /// If vCherryPickIds is empty, restores the full snapshot (delete all + insert).
  /// If vCherryPickIds is non-empty, restores only the specified record IDs.
  /// Does NOT push to providers — operator must preview + push afterward.
  void apply(int64_t iZoneId, int64_t iDeploymentId,
             const std::vector<int64_t>& vCherryPickIds,
             int64_t iActorUserId, const std::string& sActor);

 private:
  dns::dal::DeploymentRepository& _drRepo;
  dns::dal::RecordRepository& _rrRepo;
  dns::dal::AuditRepository& _arRepo;
};

}  // namespace dns::core
