#include "core/DiffEngine.hpp"

#include <algorithm>
#include <chrono>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "common/Errors.hpp"
#include "common/Logger.hpp"
#include "core/VariableEngine.hpp"
#include "dal/ProviderRepository.hpp"
#include "dal/RecordRepository.hpp"
#include "dal/ViewRepository.hpp"
#include "dal/ZoneRepository.hpp"
#include "providers/ProviderFactory.hpp"

namespace dns::core {

DiffEngine::DiffEngine(dns::dal::ZoneRepository& zrRepo,
                       dns::dal::ViewRepository& vrRepo,
                       dns::dal::RecordRepository& rrRepo,
                       dns::dal::ProviderRepository& prRepo,
                       VariableEngine& veEngine)
    : _zrRepo(zrRepo),
      _vrRepo(vrRepo),
      _rrRepo(rrRepo),
      _prRepo(prRepo),
      _veEngine(veEngine) {}

DiffEngine::~DiffEngine() = default;

std::vector<common::RecordDiff> DiffEngine::computeDiff(
    const std::vector<common::DnsRecord>& vDesired,
    const std::vector<common::DnsRecord>& vLive) {
  std::vector<common::RecordDiff> vDiffs;

  // Index live records by (name, type, value) for exact-match lookup
  std::set<std::string> sLiveKeys;
  for (const auto& dr : vLive) {
    sLiveKeys.insert(dr.sName + "\t" + dr.sType + "\t" + dr.sValue);
  }

  std::set<std::string> sDesiredKeys;
  for (const auto& dr : vDesired) {
    sDesiredKeys.insert(dr.sName + "\t" + dr.sType + "\t" + dr.sValue);
  }

  // Build (name, type) -> values maps for update detection
  std::map<std::string, std::vector<std::string>> mDesiredByNameType;
  for (const auto& dr : vDesired) {
    std::string sKey = dr.sName + "\t" + dr.sType;
    mDesiredByNameType[sKey].push_back(dr.sValue);
  }

  std::map<std::string, std::vector<std::string>> mLiveByNameType;
  for (const auto& dr : vLive) {
    std::string sKey = dr.sName + "\t" + dr.sType;
    mLiveByNameType[sKey].push_back(dr.sValue);
  }

  // 1. Check desired records: Add or Update
  for (const auto& dr : vDesired) {
    std::string sExactKey = dr.sName + "\t" + dr.sType + "\t" + dr.sValue;
    if (sLiveKeys.count(sExactKey)) continue;  // exact match — no diff

    std::string sNameTypeKey = dr.sName + "\t" + dr.sType;
    auto itLive = mLiveByNameType.find(sNameTypeKey);
    if (itLive != mLiveByNameType.end() && !itLive->second.empty()) {
      // Same name+type exists on provider but value differs -> Update
      std::string sProviderValue;
      for (const auto& sLiveVal : itLive->second) {
        std::string sLiveExact = dr.sName + "\t" + dr.sType + "\t" + sLiveVal;
        if (!sDesiredKeys.count(sLiveExact)) {
          sProviderValue = sLiveVal;
          break;
        }
      }
      if (!sProviderValue.empty()) {
        common::RecordDiff rd;
        rd.action = common::DiffAction::Update;
        rd.sName = dr.sName;
        rd.sType = dr.sType;
        rd.sSourceValue = dr.sValue;
        rd.sProviderValue = sProviderValue;
        rd.uTtl = dr.uTtl;
        rd.iPriority = dr.iPriority;
        vDiffs.push_back(std::move(rd));
      } else {
        common::RecordDiff rd;
        rd.action = common::DiffAction::Add;
        rd.sName = dr.sName;
        rd.sType = dr.sType;
        rd.sSourceValue = dr.sValue;
        rd.uTtl = dr.uTtl;
        rd.iPriority = dr.iPriority;
        vDiffs.push_back(std::move(rd));
      }
    } else {
      common::RecordDiff rd;
      rd.action = common::DiffAction::Add;
      rd.sName = dr.sName;
      rd.sType = dr.sType;
      rd.sSourceValue = dr.sValue;
      rd.uTtl = dr.uTtl;
      rd.iPriority = dr.iPriority;
      vDiffs.push_back(std::move(rd));
    }
  }

  // 2. Check live records for drift
  for (const auto& dr : vLive) {
    std::string sExactKey = dr.sName + "\t" + dr.sType + "\t" + dr.sValue;
    if (sDesiredKeys.count(sExactKey)) continue;

    // Check if consumed by an Update
    bool bConsumedByUpdate = false;
    for (const auto& diff : vDiffs) {
      if (diff.action == common::DiffAction::Update && diff.sName == dr.sName &&
          diff.sType == dr.sType && diff.sProviderValue == dr.sValue) {
        bConsumedByUpdate = true;
        break;
      }
    }
    if (bConsumedByUpdate) continue;

    common::RecordDiff rd;
    rd.action = common::DiffAction::Drift;
    rd.sName = dr.sName;
    rd.sType = dr.sType;
    rd.sProviderValue = dr.sValue;
    rd.uTtl = dr.uTtl;
    rd.iPriority = dr.iPriority;
    vDiffs.push_back(std::move(rd));
  }

  return vDiffs;
}

std::vector<common::DnsRecord> DiffEngine::filterRecordTypes(
    const std::vector<common::DnsRecord>& vRecords,
    bool bIncludeSoa, bool bIncludeNs) {
  std::vector<common::DnsRecord> vFiltered;
  vFiltered.reserve(vRecords.size());
  for (const auto& dr : vRecords) {
    if (!bIncludeSoa && dr.sType == "SOA") continue;
    if (!bIncludeNs && dr.sType == "NS") continue;
    vFiltered.push_back(dr);
  }
  return vFiltered;
}

common::PreviewResult DiffEngine::preview(int64_t iZoneId) {
  auto spLog = common::Logger::get();

  // 1. Look up zone
  auto oZone = _zrRepo.findById(iZoneId);
  if (!oZone) {
    throw common::NotFoundError("ZONE_NOT_FOUND",
                                "Zone " + std::to_string(iZoneId) + " not found");
  }

  // 2. Look up view with providers
  auto oView = _vrRepo.findWithProviders(oZone->iViewId);
  if (!oView) {
    throw common::NotFoundError("VIEW_NOT_FOUND",
                                "View " + std::to_string(oZone->iViewId) + " not found");
  }
  if (oView->vProviderIds.empty()) {
    throw common::ValidationError("NO_PROVIDERS",
                                  "View '" + oView->sName + "' has no providers attached");
  }

  // 3. Fetch desired records from DB and expand templates
  auto vRecordRows = _rrRepo.listByZoneId(iZoneId);
  std::vector<common::DnsRecord> vDesired;
  vDesired.reserve(vRecordRows.size());
  for (const auto& row : vRecordRows) {
    common::DnsRecord dr;
    dr.sName = row.sName;
    dr.sType = row.sType;
    dr.uTtl = static_cast<uint32_t>(row.iTtl);
    dr.sValue = _veEngine.expand(row.sValueTemplate, iZoneId);
    dr.iPriority = row.iPriority;
    vDesired.push_back(std::move(dr));
  }

  // 4. Fetch live records from all providers for this zone
  std::vector<common::DnsRecord> vLive;
  for (int64_t iProviderId : oView->vProviderIds) {
    auto oProvider = _prRepo.findById(iProviderId);
    if (!oProvider) {
      spLog->warn("Provider {} not found — skipping", iProviderId);
      continue;
    }

    auto upProvider = dns::providers::ProviderFactory::create(
        oProvider->sType, oProvider->sApiEndpoint, oProvider->sDecryptedToken,
        oProvider->jConfig);

    try {
      auto vProviderRecords = upProvider->listRecords(oZone->sName);
      vLive.insert(vLive.end(), vProviderRecords.begin(), vProviderRecords.end());
    } catch (const common::ProviderError& ex) {
      spLog->error("Failed to list records from provider '{}': {}", oProvider->sName, ex.what());
      throw;
    }
  }

  // 5. Filter SOA/NS from both sets based on zone flags
  vLive = filterRecordTypes(vLive, oZone->bManageSoa, oZone->bManageNs);
  vDesired = filterRecordTypes(vDesired, oZone->bManageSoa, oZone->bManageNs);

  // 6. Compute diff
  auto vDiffs = computeDiff(vDesired, vLive);

  // 7. Build result
  common::PreviewResult pr;
  pr.iZoneId = iZoneId;
  pr.sZoneName = oZone->sName;
  pr.vDiffs = std::move(vDiffs);
  pr.bHasDrift = std::any_of(pr.vDiffs.begin(), pr.vDiffs.end(),
                              [](const common::RecordDiff& rd) {
                                return rd.action == common::DiffAction::Drift;
                              });
  pr.tpGeneratedAt = std::chrono::system_clock::now();

  spLog->info("DiffEngine: zone '{}' — {} diffs, drift={}", oZone->sName, pr.vDiffs.size(),
              pr.bHasDrift);
  return pr;
}

}  // namespace dns::core
