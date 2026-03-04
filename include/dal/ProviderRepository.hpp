#pragma once

#include <chrono>
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

/// Row type returned from provider queries.
struct ProviderRow {
  int64_t iId = 0;
  std::string sName;
  std::string sType;
  std::string sApiEndpoint;
  std::string sDecryptedToken;
  std::chrono::system_clock::time_point tpCreatedAt;
  std::chrono::system_clock::time_point tpUpdatedAt;
};

/// Manages the providers table; decrypts tokens on read.
/// Class abbreviation: pr
class ProviderRepository {
 public:
  ProviderRepository(ConnectionPool& cpPool,
                     const dns::security::CryptoService& csService);
  ~ProviderRepository();

  /// Create a provider. Encrypts the token before INSERT. Returns the new ID.
  int64_t create(const std::string& sName, const std::string& sType,
                 const std::string& sApiEndpoint,
                 const std::string& sPlaintextToken);

  /// List all providers. Decrypts tokens.
  std::vector<ProviderRow> listAll();

  /// Find a provider by ID. Returns nullopt if not found.
  std::optional<ProviderRow> findById(int64_t iId);

  /// Update a provider. Re-encrypts token only if oPlaintextToken has a value.
  void update(int64_t iId, const std::string& sName,
              const std::string& sApiEndpoint,
              const std::optional<std::string>& oPlaintextToken);

  /// Delete a provider by ID. Throws NotFoundError if not found.
  void deleteById(int64_t iId);

 private:
  ConnectionPool& _cpPool;
  const dns::security::CryptoService& _csService;

  ProviderRow mapRow(const pqxx::row& row) const;
};

}  // namespace dns::dal
