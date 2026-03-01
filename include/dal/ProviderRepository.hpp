#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace dns::security {
class CryptoService;
}

namespace dns::dal {

class ConnectionPool;

/// Row type returned from provider queries (list view — no token).
struct ProviderRow {
  int64_t iId = 0;
  std::string sName;
  std::string sType;
  std::string sApiEndpoint;
  std::string sCreatedAt;
  std::string sUpdatedAt;
};

/// Row type returned from provider queries (detail view — decrypted token).
struct ProviderDetailRow {
  int64_t iId = 0;
  std::string sName;
  std::string sType;
  std::string sApiEndpoint;
  std::string sDecryptedToken;
  std::string sCreatedAt;
  std::string sUpdatedAt;
};

/// Manages the providers table; encrypts tokens on write, decrypts on read.
/// Class abbreviation: pr
class ProviderRepository {
 public:
  ProviderRepository(ConnectionPool& cpPool,
                     const dns::security::CryptoService& csService);
  ~ProviderRepository();

  /// Create a provider. Encrypts the raw token before storage.
  /// Returns the new provider ID.
  /// Throws ConflictError if name already exists.
  int64_t create(const std::string& sName, const std::string& sType,
                 const std::string& sApiEndpoint, const std::string& sRawToken);

  /// Find a provider by ID with decrypted token.
  /// Returns nullopt if not found.
  std::optional<ProviderDetailRow> findById(int64_t iProviderId);

  /// List all providers (no tokens in result).
  std::vector<ProviderRow> list();

  /// Update a provider. Encrypts the new token if provided.
  /// Throws NotFoundError if provider doesn't exist.
  void update(int64_t iProviderId, const std::string& sName,
              const std::string& sType, const std::string& sApiEndpoint,
              const std::string& sRawToken);

  /// Delete a provider by ID.
  /// Throws NotFoundError if provider doesn't exist.
  void deleteById(int64_t iProviderId);

 private:
  ConnectionPool& _cpPool;
  const dns::security::CryptoService& _csService;
};

}  // namespace dns::dal
