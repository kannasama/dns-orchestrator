#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace pqxx {
class row;
}

namespace dns::security {
class CryptoService;
}

namespace dns::dal {

class ConnectionPool;

/// Row returned from identity_providers table.
struct IdpRow {
  int64_t iId = 0;
  std::string sName;
  std::string sType;             // "oidc" or "saml"
  bool bIsEnabled = true;
  nlohmann::json jConfig;        // Type-specific configuration
  std::string sDecryptedSecret;  // Only populated by findById(), empty in list
  nlohmann::json jGroupMappings;
  int64_t iDefaultGroupId = 0;
  std::string sCreatedAt;
  std::string sUpdatedAt;
};

/// CRUD for identity_providers table.
/// Class abbreviation: ir
class IdpRepository {
 public:
  IdpRepository(ConnectionPool& cpPool, const dns::security::CryptoService& csService);
  ~IdpRepository();

  int64_t create(const std::string& sName, const std::string& sType,
                 const nlohmann::json& jConfig, const std::string& sPlaintextSecret,
                 const nlohmann::json& jGroupMappings, int64_t iDefaultGroupId);

  std::optional<IdpRow> findById(int64_t iId);
  std::vector<IdpRow> listAll();
  std::vector<IdpRow> listEnabled();

  void update(int64_t iId, const std::string& sName, bool bIsEnabled,
              const nlohmann::json& jConfig, const std::string& sPlaintextSecret,
              const nlohmann::json& jGroupMappings, int64_t iDefaultGroupId);

  void deleteIdp(int64_t iId);

 private:
  IdpRow mapRow(const pqxx::row& row, bool bDecryptSecret = false) const;

  ConnectionPool& _cpPool;
  const dns::security::CryptoService& _csService;
};

}  // namespace dns::dal
