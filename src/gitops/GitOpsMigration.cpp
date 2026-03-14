#include "gitops/GitOpsMigration.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>

#include <nlohmann/json.hpp>

#include "common/Logger.hpp"
#include "dal/GitRepoRepository.hpp"
#include "dal/ZoneRepository.hpp"

namespace dns::gitops {

bool GitOpsMigration::migrateIfNeeded(dns::dal::GitRepoRepository& grRepo,
                                      dns::dal::ZoneRepository& zrRepo) {
  auto spLog = common::Logger::get();

  // Check if legacy env var is set
  const char* pRemoteUrl = std::getenv("DNS_GIT_REMOTE_URL");
  if (!pRemoteUrl || std::string(pRemoteUrl).empty()) {
    return false;
  }

  // Check if any git_repos already exist (migration already done)
  auto vExisting = grRepo.listAll();
  if (!vExisting.empty()) {
    spLog->info("GitOpsMigration: git_repos table already populated — "
                "ignoring DNS_GIT_REMOTE_URL env var");
    return false;
  }

  std::string sRemoteUrl(pRemoteUrl);
  spLog->info("GitOpsMigration: migrating DNS_GIT_REMOTE_URL='{}' to git_repos table",
              sRemoteUrl);

  // Read SSH key file if configured
  std::string sAuthType = "none";
  std::string sCredentials;
  std::string sKnownHosts;

  const char* pSshKeyPath = std::getenv("DNS_GIT_SSH_KEY_PATH");
  if (pSshKeyPath && std::string(pSshKeyPath).length() > 0) {
    sAuthType = "ssh";
    std::ifstream ifs(pSshKeyPath);
    if (ifs.is_open()) {
      std::ostringstream oss;
      oss << ifs.rdbuf();
      nlohmann::json jCreds = {
          {"private_key", oss.str()},
          {"passphrase", ""},
      };
      sCredentials = jCreds.dump();
      spLog->info("GitOpsMigration: read SSH key from '{}'", pSshKeyPath);
    } else {
      spLog->warn("GitOpsMigration: could not read SSH key from '{}'", pSshKeyPath);
    }
  }

  const char* pKnownHosts = std::getenv("DNS_GIT_KNOWN_HOSTS_FILE");
  if (pKnownHosts && std::string(pKnownHosts).length() > 0) {
    std::ifstream ifs(pKnownHosts);
    if (ifs.is_open()) {
      std::ostringstream oss;
      oss << ifs.rdbuf();
      sKnownHosts = oss.str();
    }
  }

  // Determine default branch
  std::string sDefaultBranch = "main";

  // Determine local path from existing env var
  const char* pLocalPath = std::getenv("DNS_GIT_LOCAL_PATH");
  std::string sLocalPath = pLocalPath ? std::string(pLocalPath) : "";

  // Create the git_repos row
  int64_t iRepoId = grRepo.create("default", sRemoteUrl, sAuthType,
                                  sCredentials, sDefaultBranch, sLocalPath, sKnownHosts);
  spLog->info("GitOpsMigration: created git_repos row id={}", iRepoId);

  // Assign all existing zones to this repo
  auto vZones = zrRepo.listAll();
  for (const auto& zone : vZones) {
    zrRepo.update(zone.iId, zone.sName, zone.iViewId, zone.oDeploymentRetention,
                  zone.bManageSoa, zone.bManageNs, iRepoId, std::nullopt);
  }
  spLog->info("GitOpsMigration: assigned {} existing zone(s) to repo '{}'",
              vZones.size(), "default");

  spLog->warn("GitOpsMigration: DNS_GIT_REMOTE_URL env var is DEPRECATED. "
              "Git repos are now managed via the admin UI. "
              "The env var will be ignored on subsequent starts.");

  return true;
}

}  // namespace dns::gitops
