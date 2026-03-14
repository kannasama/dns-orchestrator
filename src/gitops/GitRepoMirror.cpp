#include "gitops/GitRepoMirror.hpp"

#include <filesystem>
#include <fstream>
#include <sstream>

#include <git2.h>

#include "common/Errors.hpp"
#include "common/Logger.hpp"

namespace dns::gitops {

GitRepoMirror::GitRepoMirror(int64_t iRepoId, const std::string& sName)
    : _iRepoId(iRepoId), _sName(sName) {
  git_libgit2_init();
}

GitRepoMirror::~GitRepoMirror() {
  if (_pRepo) git_repository_free(_pRepo);
  git_libgit2_shutdown();
}

// ── libgit2 callbacks ──────────────────────────────────────────────────────

int GitRepoMirror::credentialsCb(git_credential** ppOut, const char* /*pUrl*/,
                                  const char* pUsernameFromUrl, unsigned int iAllowedTypes,
                                  void* pPayload) {
  auto* pSelf = static_cast<const GitRepoMirror*>(pPayload);

  if ((iAllowedTypes & GIT_CREDENTIAL_SSH_KEY) &&
      pSelf->_auth.sAuthType == "ssh" && !pSelf->_auth.sPrivateKey.empty()) {
    const char* pUsername = (pUsernameFromUrl && pUsernameFromUrl[0])
                                ? pUsernameFromUrl : "git";
    return git_credential_ssh_key_memory_new(
        ppOut, pUsername, nullptr,
        pSelf->_auth.sPrivateKey.c_str(),
        pSelf->_auth.sPassphrase.empty() ? nullptr : pSelf->_auth.sPassphrase.c_str());
  }

  if ((iAllowedTypes & GIT_CREDENTIAL_USERPASS_PLAINTEXT) &&
      pSelf->_auth.sAuthType == "https" && !pSelf->_auth.sToken.empty()) {
    return git_credential_userpass_plaintext_new(
        ppOut,
        pSelf->_auth.sUsername.empty() ? "oauth2" : pSelf->_auth.sUsername.c_str(),
        pSelf->_auth.sToken.c_str());
  }

  return GIT_PASSTHROUGH;
}

int GitRepoMirror::certificateCheckCb(git_cert* /*pCert*/, int /*bValid*/,
                                       const char* pHost, void* pPayload) {
  auto* pSelf = static_cast<const GitRepoMirror*>(pPayload);

  if (pSelf->_auth.sKnownHosts.empty()) {
    // No known_hosts configured — accept all hosts
    return 0;
  }

  std::string sHost(pHost ? pHost : "");
  std::istringstream iss(pSelf->_auth.sKnownHosts);
  std::string sLine;
  while (std::getline(iss, sLine)) {
    if (sLine.empty() || sLine[0] == '#') continue;
    auto iSpace = sLine.find(' ');
    if (iSpace == std::string::npos) continue;
    std::string sHosts = sLine.substr(0, iSpace);
    std::istringstream issHosts(sHosts);
    std::string sEntry;
    while (std::getline(issHosts, sEntry, ',')) {
      if (!sEntry.empty() && sEntry[0] == '[') {
        auto iBracket = sEntry.find(']');
        if (iBracket != std::string::npos) {
          sEntry = sEntry.substr(1, iBracket - 1);
        }
      }
      if (sEntry == sHost) {
        return 0;  // Host found — accept
      }
    }
  }

  auto spLog = common::Logger::get();
  spLog->error("GitRepoMirror[{}]: host '{}' not found in known_hosts", pSelf->_sName, sHost);
  return GIT_ECERTIFICATE;
}

// ── Options helpers ─────────────────────────────────────────────────────────

namespace {

void applyRemoteCallbacks(git_remote_callbacks& cb, GitRepoMirror* pMirror,
                          const GitRepoAuth& auth) {
  if (auth.sAuthType == "ssh" || auth.sAuthType == "https") {
    cb.credentials = &GitRepoMirror::credentialsCb;
  }
  cb.certificate_check = &GitRepoMirror::certificateCheckCb;
  cb.payload = pMirror;
}

}  // namespace

// ── SSH home setup ──────────────────────────────────────────────────────────

void GitRepoMirror::setupSshHome() {
  namespace fs = std::filesystem;
  fs::path sshHome = fs::path(_sLocalPath).parent_path() / ".gitssh";
  fs::path sshDir = sshHome / ".ssh";
  fs::create_directories(sshDir);
  fs::path knownHostsPath = sshDir / "known_hosts";

  if (!_auth.sKnownHosts.empty()) {
    // Write known_hosts content from memory
    std::ofstream ofs(knownHostsPath);
    ofs << _auth.sKnownHosts;
    ofs.close();
  } else if (!fs::exists(knownHostsPath)) {
    // Create empty known_hosts so libgit2 SSH transport doesn't error
    std::ofstream ofs(knownHostsPath);
    ofs.close();
  }
  git_libgit2_opts(GIT_OPT_SET_HOMEDIR, sshHome.c_str());
}

// ── Core operations ─────────────────────────────────────────────────────────

void GitRepoMirror::initialize(const std::string& sRemoteUrl, const std::string& sLocalPath,
                                const std::string& sDefaultBranch, const GitRepoAuth& auth) {
  auto spLog = common::Logger::get();
  _sRemoteUrl = sRemoteUrl;
  _sLocalPath = sLocalPath;
  _sDefaultBranch = sDefaultBranch;
  _auth = auth;

  namespace fs = std::filesystem;

  setupSshHome();

  if (fs::exists(sLocalPath + "/.git") || fs::exists(sLocalPath + "/HEAD")) {
    int iErr = git_repository_open(&_pRepo, sLocalPath.c_str());
    if (iErr < 0) {
      const git_error* pErr = git_error_last();
      spLog->error("GitRepoMirror[{}]: failed to open repo at '{}': {}", _sName, sLocalPath,
                   pErr ? pErr->message : "unknown");
      throw common::GitMirrorError("GIT_OPEN_FAILED",
                                   "Failed to open git repo: " +
                                       std::string(pErr ? pErr->message : "unknown"));
    }
    spLog->info("GitRepoMirror[{}]: opened existing repo at '{}'", _sName, sLocalPath);
  } else if (!sRemoteUrl.empty()) {
    fs::create_directories(sLocalPath);

    git_clone_options cloneOpts;
    git_clone_options_init(&cloneOpts, GIT_CLONE_OPTIONS_VERSION);
    applyRemoteCallbacks(cloneOpts.fetch_opts.callbacks, this, _auth);

    int iErr = git_clone(&_pRepo, sRemoteUrl.c_str(), sLocalPath.c_str(), &cloneOpts);
    if (iErr < 0) {
      const git_error* pErr = git_error_last();
      spLog->error("GitRepoMirror[{}]: failed to clone '{}' to '{}': {}", _sName,
                   sRemoteUrl, sLocalPath, pErr ? pErr->message : "unknown");
      throw common::GitMirrorError("GIT_CLONE_FAILED",
                                   "Failed to clone git repo: " +
                                       std::string(pErr ? pErr->message : "unknown"));
    }
    spLog->info("GitRepoMirror[{}]: cloned '{}' to '{}'", _sName, sRemoteUrl, sLocalPath);
  } else {
    // No remote and no existing repo — init a bare local repo
    fs::create_directories(sLocalPath);
    int iErr = git_repository_init(&_pRepo, sLocalPath.c_str(), 0);
    if (iErr < 0) {
      const git_error* pErr = git_error_last();
      throw common::GitMirrorError("GIT_INIT_FAILED",
                                   "Failed to init git repo: " +
                                       std::string(pErr ? pErr->message : "unknown"));
    }
    spLog->info("GitRepoMirror[{}]: initialized new repo at '{}'", _sName, sLocalPath);
  }
}

void GitRepoMirror::pull() {
  if (!_pRepo || _sRemoteUrl.empty()) return;

  std::lock_guard lock(_mtx);
  auto spLog = common::Logger::get();

  git_remote* pRemote = nullptr;
  int iErr = git_remote_lookup(&pRemote, _pRepo, "origin");
  if (iErr < 0) {
    spLog->warn("GitRepoMirror[{}]: no 'origin' remote — skipping pull", _sName);
    return;
  }

  git_fetch_options fetchOpts;
  git_fetch_options_init(&fetchOpts, GIT_FETCH_OPTIONS_VERSION);
  applyRemoteCallbacks(fetchOpts.callbacks, this, _auth);

  iErr = git_remote_fetch(pRemote, nullptr, &fetchOpts, nullptr);
  git_remote_free(pRemote);
  if (iErr < 0) {
    const git_error* pErr = git_error_last();
    spLog->warn("GitRepoMirror[{}]: fetch failed: {}", _sName,
                pErr ? pErr->message : "unknown");
  } else {
    spLog->info("GitRepoMirror[{}]: fetched from origin", _sName);
  }
}

void GitRepoMirror::checkoutBranch(const std::string& sBranch) {
  if (!_pRepo || sBranch.empty()) return;

  auto spLog = common::Logger::get();
  std::string sRefLocal = "refs/heads/" + sBranch;
  std::string sRefRemote = "refs/remotes/origin/" + sBranch;

  git_reference* pRef = nullptr;
  int iErr = git_reference_lookup(&pRef, _pRepo, sRefLocal.c_str());

  if (iErr < 0) {
    // Try creating from remote tracking branch
    git_reference* pRemoteRef = nullptr;
    iErr = git_reference_lookup(&pRemoteRef, _pRepo, sRefRemote.c_str());
    if (iErr == 0) {
      const git_oid* pOid = git_reference_target(pRemoteRef);
      git_reference_create(&pRef, _pRepo, sRefLocal.c_str(), pOid, 0, nullptr);
      git_reference_free(pRemoteRef);
    } else {
      // Create branch from HEAD
      git_reference* pHead = nullptr;
      if (git_repository_head(&pHead, _pRepo) == 0) {
        const git_oid* pOid = git_reference_target(pHead);
        git_reference_create(&pRef, _pRepo, sRefLocal.c_str(), pOid, 0, nullptr);
        git_reference_free(pHead);
      }
    }
  }

  if (pRef) {
    // Checkout the branch
    git_object* pTarget = nullptr;
    git_reference_peel(&pTarget, pRef, GIT_OBJECT_COMMIT);
    if (pTarget) {
      git_checkout_options opts;
      git_checkout_options_init(&opts, GIT_CHECKOUT_OPTIONS_VERSION);
      opts.checkout_strategy = GIT_CHECKOUT_FORCE;
      git_checkout_tree(_pRepo, pTarget, &opts);
      git_repository_set_head(_pRepo, sRefLocal.c_str());
      git_object_free(pTarget);
    }
    git_reference_free(pRef);
    spLog->debug("GitRepoMirror[{}]: checked out branch '{}'", _sName, sBranch);
  }
}

void GitRepoMirror::gitAddCommitPush(const std::string& sMessage, const std::string& sBranch) {
  if (!_pRepo) return;
  auto spLog = common::Logger::get();

  // Stage all changes
  git_index* pIndex = nullptr;
  git_repository_index(&pIndex, _pRepo);
  git_index_add_all(pIndex, nullptr, 0, nullptr, nullptr);
  git_index_write(pIndex);

  // Create tree from index
  git_oid treeOid;
  git_index_write_tree(&treeOid, pIndex);
  git_index_free(pIndex);

  git_tree* pTree = nullptr;
  git_tree_lookup(&pTree, _pRepo, &treeOid);

  // Get HEAD commit as parent (if exists)
  git_reference* pHead = nullptr;
  git_commit* pParent = nullptr;
  bool bHasParent = false;
  if (git_repository_head(&pHead, _pRepo) == 0) {
    git_oid parentOid;
    git_reference_name_to_id(&parentOid, _pRepo, "HEAD");
    git_commit_lookup(&pParent, _pRepo, &parentOid);
    bHasParent = true;
  }

  // Create commit
  git_signature* pSig = nullptr;
  git_signature_now(&pSig, "meridian-dns", "meridian@dns.local");

  git_oid commitOid;
  const git_commit* vParents[] = {pParent};
  git_commit_create(&commitOid, _pRepo, "HEAD", pSig, pSig, "UTF-8", sMessage.c_str(),
                    pTree, bHasParent ? 1 : 0, bHasParent ? vParents : nullptr);

  git_signature_free(pSig);
  git_tree_free(pTree);
  if (pParent) git_commit_free(pParent);
  if (pHead) git_reference_free(pHead);

  // Push to origin
  if (_sRemoteUrl.empty()) {
    spLog->info("GitRepoMirror[{}]: no remote URL — skipping push", _sName);
  } else {
    git_remote* pRemote = nullptr;
    int iLookup = git_remote_lookup(&pRemote, _pRepo, "origin");
    if (iLookup != 0) {
      spLog->warn("GitRepoMirror[{}]: no 'origin' remote — skipping push", _sName);
    } else {
      std::string sRefName = "refs/heads/" +
          (sBranch.empty() ? _sDefaultBranch : sBranch);
      std::string sRefspec = sRefName + ":" + sRefName;

      const char* vRefspecs[] = {sRefspec.c_str()};
      git_strarray refspecs = {const_cast<char**>(vRefspecs), 1};

      git_push_options pushOpts;
      git_push_options_init(&pushOpts, GIT_PUSH_OPTIONS_VERSION);
      applyRemoteCallbacks(pushOpts.callbacks, this, _auth);

      int iErr = git_remote_push(pRemote, &refspecs, &pushOpts);
      if (iErr < 0) {
        const git_error* pErr = git_error_last();
        spLog->warn("GitRepoMirror[{}]: push failed: {}", _sName,
                    pErr ? pErr->message : "unknown");
      } else {
        spLog->info("GitRepoMirror[{}]: pushed to origin ({})", _sName, sRefspec);
      }
      git_remote_free(pRemote);
    }
  }
}

void GitRepoMirror::commitSnapshot(const std::string& sRelativePath,
                                    const std::string& sContent,
                                    const std::string& sCommitMessage,
                                    const std::string& sBranch) {
  std::lock_guard lock(_mtx);
  auto spLog = common::Logger::get();

  std::string sEffectiveBranch = sBranch.empty() ? _sDefaultBranch : sBranch;

  // Checkout target branch
  checkoutBranch(sEffectiveBranch);

  // Write the file
  namespace fs = std::filesystem;
  fs::path filePath = fs::path(_sLocalPath) / sRelativePath;
  fs::create_directories(filePath.parent_path());
  std::ofstream ofs(filePath);
  ofs << sContent;
  ofs.close();

  // Commit and push
  gitAddCommitPush(sCommitMessage, sEffectiveBranch);

  // Checkout back to default branch if we switched
  if (sEffectiveBranch != _sDefaultBranch) {
    checkoutBranch(_sDefaultBranch);
  }

  spLog->info("GitRepoMirror[{}]: committed '{}' on branch '{}'", _sName,
              sRelativePath, sEffectiveBranch);
}

}  // namespace dns::gitops
