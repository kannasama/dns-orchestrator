#include "core/RollbackEngine.hpp"

#include <algorithm>

#include <nlohmann/json.hpp>

#include "common/Errors.hpp"
#include "common/Logger.hpp"
#include "dal/AuditRepository.hpp"
#include "dal/DeploymentRepository.hpp"
#include "dal/RecordRepository.hpp"

namespace dns::core {

RollbackEngine::RollbackEngine(dns::dal::DeploymentRepository& drRepo,
                               dns::dal::RecordRepository& rrRepo,
                               dns::dal::AuditRepository& arRepo)
    : _drRepo(drRepo), _rrRepo(rrRepo), _arRepo(arRepo) {}

RollbackEngine::~RollbackEngine() = default;

void RollbackEngine::apply(int64_t iZoneId, int64_t iDeploymentId,
                           const std::vector<int64_t>& vCherryPickIds,
                           int64_t /*iActorUserId*/, const std::string& sActor) {
  auto spLog = common::Logger::get();

  // 1. Fetch the deployment snapshot
  auto oDeploy = _drRepo.findById(iDeploymentId);
  if (!oDeploy) {
    throw common::NotFoundError("DEPLOYMENT_NOT_FOUND",
                                "Deployment " + std::to_string(iDeploymentId) + " not found");
  }
  if (oDeploy->iZoneId != iZoneId) {
    throw common::ValidationError("ZONE_MISMATCH",
                                  "Deployment does not belong to zone " +
                                      std::to_string(iZoneId));
  }

  const auto& jSnapshot = oDeploy->jSnapshot;
  if (!jSnapshot.contains("records") || !jSnapshot["records"].is_array()) {
    throw common::ValidationError("INVALID_SNAPSHOT", "Snapshot has no records array");
  }

  // 2. Restore records
  if (vCherryPickIds.empty()) {
    // Full restore: delete all current records, then insert from snapshot
    _rrRepo.deleteAllByZoneId(iZoneId);

    for (const auto& jRec : jSnapshot["records"]) {
      std::string sName = jRec.value("name", "");
      std::string sType = jRec.value("type", "");
      int iTtl = jRec.value("ttl", 300);
      // Use value_template if present, fall back to expanded value
      std::string sValueTemplate = jRec.value("value_template", jRec.value("value", ""));
      int iPriority = jRec.value("priority", 0);

      _rrRepo.create(iZoneId, sName, sType, iTtl, sValueTemplate, iPriority);
    }

    spLog->info("RollbackEngine: full restore of zone {} from deployment {}",
                iZoneId, iDeploymentId);
  } else {
    // Cherry-pick: restore only specified record IDs
    for (int64_t iRecordId : vCherryPickIds) {
      // Find the record in the snapshot
      bool bFound = false;
      for (const auto& jRec : jSnapshot["records"]) {
        if (jRec.value("record_id", int64_t{0}) == iRecordId) {
          std::string sName = jRec.value("name", "");
          std::string sType = jRec.value("type", "");
          int iTtl = jRec.value("ttl", 300);
          std::string sValueTemplate = jRec.value("value_template", jRec.value("value", ""));
          int iPriority = jRec.value("priority", 0);

          _rrRepo.upsertById(iRecordId, iZoneId, sName, sType, iTtl, sValueTemplate, iPriority);
          bFound = true;
          break;
        }
      }
      if (!bFound) {
        spLog->warn("RollbackEngine: record {} not found in snapshot {} — skipping",
                    iRecordId, iDeploymentId);
      }
    }

    spLog->info("RollbackEngine: cherry-pick restore of {} records in zone {} from deployment {}",
                vCherryPickIds.size(), iZoneId, iDeploymentId);
  }

  // 3. Audit log
  nlohmann::json jNewValue = {
      {"deployment_id", iDeploymentId},
      {"cherry_pick_ids", vCherryPickIds},
  };
  _arRepo.insert("zone", iZoneId, "rollback", std::nullopt, jNewValue, sActor,
                 std::nullopt, std::nullopt);
}

}  // namespace dns::core
