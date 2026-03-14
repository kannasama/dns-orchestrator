#pragma once

#include <cstdint>
#include <mutex>
#include <string>

struct git_repository;
struct git_credential;
struct git_cert;

namespace dns::gitops {

/// Authentication configuration for a git repo mirror.
struct GitRepoAuth {
  std::string sAuthType;   // "ssh", "https", "none"
  std::string sPrivateKey; // SSH: PEM private key contents
  std::string sPassphrase; // SSH: key passphrase
  std::string sUsername;   // HTTPS: username
  std::string sToken;      // HTTPS: personal access token
  std::string sKnownHosts; // SSH: known_hosts content for host verification
};

/// Wraps a single git repository: clone/open, pull, branch checkout, commit, push.
/// All operations are serialized via an internal mutex.
/// Class abbreviation: grm
class GitRepoMirror {
 public:
  GitRepoMirror(int64_t iRepoId, const std::string& sName);
  ~GitRepoMirror();

  GitRepoMirror(const GitRepoMirror&) = delete;
  GitRepoMirror& operator=(const GitRepoMirror&) = delete;

  /// Clone or open existing repo at sLocalPath. Sets up auth config.
  void initialize(const std::string& sRemoteUrl, const std::string& sLocalPath,
                  const std::string& sDefaultBranch, const GitRepoAuth& auth);

  /// Write a snapshot file and commit+push on the specified branch.
  /// sRelativePath: path within repo (e.g., "view-name/zone.json")
  /// sBranch: branch to commit on (empty = repo default branch)
  void commitSnapshot(const std::string& sRelativePath, const std::string& sContent,
                      const std::string& sCommitMessage, const std::string& sBranch = "");

  /// Fetch latest from remote.
  void pull();

  int64_t repoId() const { return _iRepoId; }
  const std::string& name() const { return _sName; }

  /// libgit2 credentials callback.
  static int credentialsCb(git_credential** ppOut, const char* pUrl,
                           const char* pUsernameFromUrl, unsigned int iAllowedTypes,
                           void* pPayload);

  /// libgit2 certificate_check callback.
  static int certificateCheckCb(git_cert* pCert, int bValid,
                                const char* pHost, void* pPayload);

 private:
  void checkoutBranch(const std::string& sBranch);
  void gitAddCommitPush(const std::string& sMessage, const std::string& sBranch);
  void setupSshHome();

  int64_t _iRepoId;
  std::string _sName;
  std::string _sRemoteUrl;
  std::string _sLocalPath;
  std::string _sDefaultBranch;
  GitRepoAuth _auth;
  git_repository* _pRepo = nullptr;
  std::mutex _mtx;
};

}  // namespace dns::gitops
