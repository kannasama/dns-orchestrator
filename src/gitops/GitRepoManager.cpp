#include "gitops/GitRepoManager.hpp"

#include <chrono>
#include <filesystem>
#include <iomanip>
#include <sstream>

#include <nlohmann/json.hpp>

#include "common/Errors.hpp"
#include "common/Logger.hpp"
#include "core/VariableEngine.hpp"
#include "dal/GitRepoRepository.hpp"
#include "dal/RecordRepository.hpp"
#include "dal/ViewRepository.hpp"
#include "dal/ZoneRepository.hpp"
#include "gitops/GitRepoMirror.hpp"

namespace dns::gitops {

GitRepoManager::GitRepoManager(dns::dal::GitRepoRepository& grRepo,
                               dns::dal::ZoneRepository& zrRepo,
                               dns::dal::ViewRepository& vrRepo,
                               dns::dal::RecordRepository& rrRepo,
                               dns::core::VariableEngine& veEngine,
                               const std::string& sBasePath)
    : _grRepo(grRepo), _zrRepo(zrRepo), _vrRepo(vrRepo),
      _rrRepo(rrRepo), _veEngine(veEngine), _sBasePath(sBasePath) {}

GitRepoManager::~GitRepoManager() = default;

namespace {

GitRepoAuth buildAuth(const dns::dal::GitRepoRow& row) {
  GitRepoAuth auth;
  auth.sAuthType = row.sAuthType;
  auth.sKnownHosts = row.sKnownHosts;

  if (!row.sDecryptedCredentials.empty()) {
    try {
      auto j = nlohmann::json::parse(row.sDecryptedCredentials);
      if (row.sAuthType == "ssh") {
        auth.sPrivateKey = j.value("private_key", "");
        auth.sPassphrase = j.value("passphrase", "");
      } else if (row.sAuthType == "https") {
        auth.sUsername = j.value("username", "");
        auth.sToken = j.value("token", "");
      }
    } catch (...) {
      // Malformed credentials JSON — leave auth fields empty
    }
  }

  return auth;
}

std::string computeLocalPath(const std::string& sBasePath, int64_t iRepoId,
                             const std::string& sConfiguredPath) {
  if (!sConfiguredPath.empty()) return sConfiguredPath;
  return sBasePath + "/" + std::to_string(iRepoId);
}

}  // namespace

void GitRepoManager::initialize() {
  std::lock_guard lock(_mtx);
  auto spLog = common::Logger::get();

  auto vRepos = _grRepo.listEnabled();
  for (auto& repoRow : vRepos) {
    // listEnabled doesn't decrypt — need findById for credentials
    auto oRepo = _grRepo.findById(repoRow.iId);
    if (!oRepo) continue;

    auto sLocalPath = computeLocalPath(_sBasePath, oRepo->iId, oRepo->sLocalPath);
    auto auth = buildAuth(*oRepo);

    try {
      auto upMirror = std::make_unique<GitRepoMirror>(oRepo->iId, oRepo->sName);
      upMirror->initialize(oRepo->sRemoteUrl, sLocalPath, oRepo->sDefaultBranch, auth);
      upMirror->pull();
      _mMirrors[oRepo->iId] = std::move(upMirror);
      _grRepo.updateSyncStatus(oRepo->iId, "success");
      spLog->info("GitRepoManager: initialized repo '{}' (id={})", oRepo->sName, oRepo->iId);
    } catch (const std::exception& ex) {
      _grRepo.updateSyncStatus(oRepo->iId, "failed", ex.what());
      spLog->error("GitRepoManager: failed to initialize repo '{}': {}",
                   oRepo->sName, ex.what());
    }
  }

  spLog->info("GitRepoManager: initialized {} repo mirror(s)", _mMirrors.size());
}

void GitRepoManager::reloadRepo(int64_t iRepoId) {
  std::lock_guard lock(_mtx);
  auto spLog = common::Logger::get();

  // Remove existing mirror if present
  _mMirrors.erase(iRepoId);

  auto oRepo = _grRepo.findById(iRepoId);
  if (!oRepo || !oRepo->bIsEnabled) {
    spLog->info("GitRepoManager: repo {} removed/disabled — mirror unloaded", iRepoId);
    return;
  }

  auto sLocalPath = computeLocalPath(_sBasePath, oRepo->iId, oRepo->sLocalPath);
  auto auth = buildAuth(*oRepo);

  try {
    auto upMirror = std::make_unique<GitRepoMirror>(oRepo->iId, oRepo->sName);
    upMirror->initialize(oRepo->sRemoteUrl, sLocalPath, oRepo->sDefaultBranch, auth);
    upMirror->pull();
    _mMirrors[oRepo->iId] = std::move(upMirror);
    _grRepo.updateSyncStatus(oRepo->iId, "success");
    spLog->info("GitRepoManager: reloaded repo '{}' (id={})", oRepo->sName, oRepo->iId);
  } catch (const std::exception& ex) {
    _grRepo.updateSyncStatus(oRepo->iId, "failed", ex.what());
    spLog->error("GitRepoManager: failed to reload repo '{}': {}",
                 oRepo->sName, ex.what());
  }
}

void GitRepoManager::removeRepo(int64_t iRepoId) {
  std::lock_guard lock(_mtx);
  _mMirrors.erase(iRepoId);
}

GitRepoMirror* GitRepoManager::findMirror(int64_t iRepoId) {
  auto it = _mMirrors.find(iRepoId);
  return (it != _mMirrors.end()) ? it->second.get() : nullptr;
}

std::string GitRepoManager::buildSnapshotJson(int64_t iZoneId,
                                              const std::string& sActor) const {
  auto oZone = _zrRepo.findById(iZoneId);
  if (!oZone) {
    throw common::NotFoundError("ZONE_NOT_FOUND",
                                "Zone " + std::to_string(iZoneId) + " not found");
  }

  auto oView = _vrRepo.findById(oZone->iViewId);
  std::string sViewName = oView ? oView->sName : "unknown";

  auto vRecords = _rrRepo.listByZoneId(iZoneId);

  nlohmann::json jRecords = nlohmann::json::array();
  for (const auto& rec : vRecords) {
    std::string sExpandedValue;
    try {
      sExpandedValue = _veEngine.expand(rec.sValueTemplate, iZoneId);
    } catch (...) {
      sExpandedValue = rec.sValueTemplate;
    }
    jRecords.push_back({
        {"record_id", rec.iId},
        {"name", rec.sName},
        {"type", rec.sType},
        {"ttl", rec.iTtl},
        {"value_template", rec.sValueTemplate},
        {"value", sExpandedValue},
        {"priority", rec.iPriority},
    });
  }

  auto tpNow = std::chrono::system_clock::now();
  auto ttNow = std::chrono::system_clock::to_time_t(tpNow);
  std::ostringstream oss;
  oss << std::put_time(std::gmtime(&ttNow), "%FT%TZ");

  nlohmann::json j = {
      {"zone", oZone->sName},
      {"view", sViewName},
      {"generated_at", oss.str()},
      {"generated_by", sActor},
      {"records", jRecords},
  };
  return j.dump(2);
}

void GitRepoManager::commitZoneSnapshot(int64_t iZoneId, const std::string& sActor) {
  auto spLog = common::Logger::get();

  auto oZone = _zrRepo.findById(iZoneId);
  if (!oZone || !oZone->oGitRepoId.has_value()) {
    // Zone has no git repo assigned — no-op
    return;
  }

  int64_t iRepoId = *oZone->oGitRepoId;
  GitRepoMirror* pMirror = nullptr;
  {
    std::lock_guard lock(_mtx);
    pMirror = findMirror(iRepoId);
  }

  if (!pMirror) {
    spLog->warn("GitRepoManager: repo {} not loaded — skipping commit for zone {}",
                iRepoId, iZoneId);
    return;
  }

  try {
    auto oView = _vrRepo.findById(oZone->iViewId);
    std::string sViewName = oView ? oView->sName : "unknown";

    std::string sRelPath = sViewName + "/" + oZone->sName + ".json";
    std::string sJson = buildSnapshotJson(iZoneId, sActor);
    std::string sBranch = oZone->oGitBranch.value_or("");
    std::string sMsg = "Update " + oZone->sName + " by " + sActor + " via API";

    pMirror->commitSnapshot(sRelPath, sJson, sMsg, sBranch);
    spLog->info("GitRepoManager: committed zone '{}' to repo {} branch '{}'",
                oZone->sName, iRepoId,
                sBranch.empty() ? "(default)" : sBranch);
  } catch (const std::exception& ex) {
    spLog->error("GitRepoManager: commit failed for zone {}: {}", iZoneId, ex.what());
  }
}

void GitRepoManager::pullAll() {
  std::lock_guard lock(_mtx);
  for (auto& [iId, upMirror] : _mMirrors) {
    try {
      upMirror->pull();
      _grRepo.updateSyncStatus(iId, "success");
    } catch (const std::exception& ex) {
      _grRepo.updateSyncStatus(iId, "failed", ex.what());
    }
  }
}

void GitRepoManager::pullRepo(int64_t iRepoId) {
  std::lock_guard lock(_mtx);
  auto* pMirror = findMirror(iRepoId);
  if (!pMirror) {
    throw common::NotFoundError("GIT_REPO_NOT_LOADED",
                                "Git repo " + std::to_string(iRepoId) + " is not loaded");
  }
  pMirror->pull();
  _grRepo.updateSyncStatus(iRepoId, "success");
}

std::string GitRepoManager::testConnection(int64_t iRepoId) {
  auto oRepo = _grRepo.findById(iRepoId);
  if (!oRepo) {
    return "Git repo not found";
  }

  auto auth = buildAuth(*oRepo);
  auto sTmpDir = std::filesystem::temp_directory_path() /
                 ("meridian-git-test-" + std::to_string(iRepoId));
  std::filesystem::remove_all(sTmpDir);

  try {
    GitRepoMirror testMirror(iRepoId, oRepo->sName + "-test");
    testMirror.initialize(oRepo->sRemoteUrl, sTmpDir.string(),
                         oRepo->sDefaultBranch, auth);
    std::filesystem::remove_all(sTmpDir);
    return "";  // Success
  } catch (const std::exception& ex) {
    std::filesystem::remove_all(sTmpDir);
    return ex.what();
  }
}

}  // namespace dns::gitops
