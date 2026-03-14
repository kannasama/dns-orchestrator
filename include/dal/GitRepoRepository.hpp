#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace pqxx {
class row;
}

namespace dns::security {
class CryptoService;
}

namespace dns::dal {

class ConnectionPool;

/// Row returned from git_repos queries.
struct GitRepoRow {
  int64_t iId = 0;
  std::string sName;
  std::string sRemoteUrl;
  std::string sAuthType;              // "ssh", "https", "none"
  std::string sDecryptedCredentials;  // Decrypted JSON string (only populated by findById)
  std::string sDefaultBranch;
  std::string sLocalPath;             // Auto-generated if empty
  std::string sKnownHosts;
  bool bIsEnabled = true;
  std::string sLastSyncAt;
  std::string sLastSyncStatus;        // "success", "failed", or empty
  std::string sLastSyncError;
  std::string sCreatedAt;
  std::string sUpdatedAt;
};

/// CRUD for git_repos table with encrypted credential storage.
/// Class abbreviation: gr
class GitRepoRepository {
 public:
  GitRepoRepository(ConnectionPool& cpPool, const dns::security::CryptoService& csService);
  ~GitRepoRepository();

  /// Create a git repo. Encrypts credentials before INSERT. Returns the new ID.
  int64_t create(const std::string& sName, const std::string& sRemoteUrl,
                 const std::string& sAuthType, const std::string& sPlaintextCredentials,
                 const std::string& sDefaultBranch, const std::string& sLocalPath,
                 const std::string& sKnownHosts);

  /// List all git repos. Does NOT decrypt credentials.
  std::vector<GitRepoRow> listAll();

  /// List enabled git repos. Does NOT decrypt credentials.
  std::vector<GitRepoRow> listEnabled();

  /// Find a git repo by ID. Decrypts credentials.
  std::optional<GitRepoRow> findById(int64_t iId);

  /// Find a git repo by name. Decrypts credentials.
  std::optional<GitRepoRow> findByName(const std::string& sName);

  /// Update a git repo. Re-encrypts credentials only if sPlaintextCredentials is non-empty.
  /// Sets updated_at to now().
  void update(int64_t iId, const std::string& sName, const std::string& sRemoteUrl,
              const std::string& sAuthType, const std::string& sPlaintextCredentials,
              const std::string& sDefaultBranch, const std::string& sLocalPath,
              const std::string& sKnownHosts, bool bIsEnabled);

  /// Update sync status fields after a sync operation.
  void updateSyncStatus(int64_t iId, const std::string& sStatus,
                        const std::string& sError = "");

  /// Delete a git repo by ID. Throws NotFoundError if not found.
  void deleteById(int64_t iId);

 private:
  ConnectionPool& _cpPool;
  const dns::security::CryptoService& _csService;

  GitRepoRow mapRow(const pqxx::row& row, bool bDecryptCredentials = false) const;
};

}  // namespace dns::dal
