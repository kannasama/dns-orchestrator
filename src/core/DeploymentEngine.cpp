#include "core/DeploymentEngine.hpp"

#include <chrono>
#include <iomanip>
#include <sstream>

#include <nlohmann/json.hpp>

#include "common/Errors.hpp"
#include "common/Logger.hpp"
#include "common/Types.hpp"
#include "core/DiffEngine.hpp"
#include "core/VariableEngine.hpp"
#include "dal/AuditRepository.hpp"
#include "dal/DeploymentRepository.hpp"
#include "dal/ProviderRepository.hpp"
#include "dal/RecordRepository.hpp"
#include "dal/ViewRepository.hpp"
#include "dal/ZoneRepository.hpp"
#include "gitops/GitOpsMirror.hpp"
#include "providers/ProviderFactory.hpp"

namespace dns::core {

DeploymentEngine::DeploymentEngine(DiffEngine& deEngine,
                                   VariableEngine& veEngine,
                                   dns::dal::ZoneRepository& zrRepo,
                                   dns::dal::ViewRepository& vrRepo,
                                   dns::dal::RecordRepository& rrRepo,
                                   dns::dal::ProviderRepository& prRepo,
                                   dns::dal::DeploymentRepository& drRepo,
                                   dns::dal::AuditRepository& arRepo,
                                   dns::gitops::GitOpsMirror* pGitMirror,
                                   int iRetentionCount)
    : _deEngine(deEngine),
      _veEngine(veEngine),
      _zrRepo(zrRepo),
      _vrRepo(vrRepo),
      _rrRepo(rrRepo),
      _prRepo(prRepo),
      _drRepo(drRepo),
      _arRepo(arRepo),
      _pGitMirror(pGitMirror),
      _iRetentionCount(iRetentionCount) {}

DeploymentEngine::~DeploymentEngine() = default;

std::mutex& DeploymentEngine::zoneMutex(int64_t iZoneId) {
  std::lock_guard lock(_mtxMap);
  auto it = _mZoneMutexes.find(iZoneId);
  if (it == _mZoneMutexes.end()) {
    auto [newIt, _] = _mZoneMutexes.emplace(iZoneId, std::make_unique<std::mutex>());
    return *newIt->second;
  }
  return *it->second;
}

nlohmann::json DeploymentEngine::buildSnapshot(int64_t iZoneId,
                                               const std::string& sActor) const {
  auto oZone = _zrRepo.findById(iZoneId);
  std::string sZoneName = oZone ? oZone->sName : "unknown";

  auto oView = oZone ? _vrRepo.findById(oZone->iViewId) : std::nullopt;
  std::string sViewName = oView ? oView->sName : "unknown";

  auto vRecords = _rrRepo.listByZoneId(iZoneId);

  nlohmann::json jRecords = nlohmann::json::array();
  for (const auto& rec : vRecords) {
    std::string sExpanded;
    try {
      sExpanded = _veEngine.expand(rec.sValueTemplate, iZoneId);
    } catch (...) {
      sExpanded = rec.sValueTemplate;
    }

    jRecords.push_back({
        {"record_id", rec.iId},
        {"name", rec.sName},
        {"type", rec.sType},
        {"ttl", rec.iTtl},
        {"value_template", rec.sValueTemplate},
        {"value", sExpanded},
        {"priority", rec.iPriority},
    });
  }

  auto tpNow = std::chrono::system_clock::now();
  auto ttNow = std::chrono::system_clock::to_time_t(tpNow);
  std::ostringstream oss;
  oss << std::put_time(std::gmtime(&ttNow), "%FT%TZ");

  return {
      {"zone", sZoneName},
      {"view", sViewName},
      {"deployed_at", oss.str()},
      {"deployed_by", sActor},
      {"records", jRecords},
  };
}

void DeploymentEngine::push(int64_t iZoneId, bool bPurgeDrift,
                            int64_t iActorUserId, const std::string& sActor) {
  auto spLog = common::Logger::get();

  // 1. Acquire per-zone mutex (non-blocking try_lock)
  auto& mtxZone = zoneMutex(iZoneId);
  if (!mtxZone.try_lock()) {
    throw common::DeploymentLockedError(
        "ZONE_LOCKED", "Zone " + std::to_string(iZoneId) + " is currently being deployed");
  }
  std::lock_guard lock(mtxZone, std::adopt_lock);

  // 2. Fresh preview (freshness guard against stale diffs)
  auto prResult = _deEngine.preview(iZoneId);
  spLog->info("DeploymentEngine: zone '{}' — {} diffs to push", prResult.sZoneName,
              prResult.vDiffs.size());

  if (prResult.vDiffs.empty()) {
    spLog->info("DeploymentEngine: zone '{}' — nothing to push", prResult.sZoneName);
    return;
  }

  // 3. Get zone and view with providers
  auto oZone = _zrRepo.findById(iZoneId);
  auto oView = _vrRepo.findWithProviders(oZone->iViewId);

  for (int64_t iProviderId : oView->vProviderIds) {
    auto oProvider = _prRepo.findById(iProviderId);
    if (!oProvider) continue;

    auto upProvider = dns::providers::ProviderFactory::create(
        oProvider->sType, oProvider->sApiEndpoint, oProvider->sDecryptedToken,
        oProvider->jConfig);

    // 4. Execute diffs
    for (const auto& diff : prResult.vDiffs) {
      try {
        switch (diff.action) {
          case common::DiffAction::Add: {
            common::DnsRecord dr;
            dr.sName = diff.sName;
            dr.sType = diff.sType;
            dr.sValue = diff.sSourceValue;
            auto pushResult = upProvider->createRecord(oZone->sName, dr);
            if (!pushResult.bSuccess) {
              throw common::ProviderError("PROVIDER_CREATE_FAILED",
                                         "Failed to create record: " + pushResult.sErrorMessage);
            }
            break;
          }
          case common::DiffAction::Update: {
            common::DnsRecord dr;
            dr.sName = diff.sName;
            dr.sType = diff.sType;
            dr.sValue = diff.sSourceValue;
            auto pushResult = upProvider->updateRecord(oZone->sName, dr);
            if (!pushResult.bSuccess) {
              throw common::ProviderError("PROVIDER_UPDATE_FAILED",
                                         "Failed to update record: " + pushResult.sErrorMessage);
            }
            break;
          }
          case common::DiffAction::Delete: {
            // Records marked Delete should be removed from provider
            break;
          }
          case common::DiffAction::Drift: {
            if (bPurgeDrift) {
              // Build a synthetic provider record ID for deletion
              std::string sRecordId = diff.sName + "/" + diff.sType + "/" + diff.sProviderValue;
              bool bDeleted = upProvider->deleteRecord(oZone->sName, sRecordId);
              if (!bDeleted) {
                spLog->warn("DeploymentEngine: failed to purge drift record {}/{}/{}",
                            diff.sName, diff.sType, diff.sProviderValue);
              }
            }
            break;
          }
        }
      } catch (const common::ProviderError&) {
        throw;  // Re-throw provider errors
      }
    }
  }

  // 5. Write audit log
  nlohmann::json jDiffs = nlohmann::json::array();
  for (const auto& diff : prResult.vDiffs) {
    jDiffs.push_back({
        {"action", diff.action == common::DiffAction::Add      ? "add"
                   : diff.action == common::DiffAction::Update  ? "update"
                   : diff.action == common::DiffAction::Delete  ? "delete"
                                                                 : "drift"},
        {"name", diff.sName},
        {"type", diff.sType},
        {"source_value", diff.sSourceValue},
        {"provider_value", diff.sProviderValue},
        {"ttl", diff.uTtl},
        {"priority", diff.iPriority},
    });
  }
  _arRepo.insert("zone", iZoneId, "push", std::nullopt, jDiffs, sActor,
                 std::nullopt, std::nullopt);

  // 6. Create deployment snapshot
  auto jSnapshot = buildSnapshot(iZoneId, sActor);
  _drRepo.create(iZoneId, iActorUserId, jSnapshot);

  // 7. Prune old snapshots
  int iRetention = _iRetentionCount;
  if (oZone->oDeploymentRetention.has_value() && *oZone->oDeploymentRetention >= 1) {
    iRetention = *oZone->oDeploymentRetention;
  }
  _drRepo.pruneByRetention(iZoneId, iRetention);

  // 8. GitOps mirror commit (non-fatal)
  if (_pGitMirror) {
    _pGitMirror->commit(iZoneId, sActor);
  }

  spLog->info("DeploymentEngine: zone '{}' pushed successfully by {}", prResult.sZoneName,
              sActor);
}

}  // namespace dns::core
