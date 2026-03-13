#include "dal/IdpRepository.hpp"

#include "common/Errors.hpp"
#include "dal/ConnectionPool.hpp"
#include "security/CryptoService.hpp"

#include <pqxx/pqxx>

namespace dns::dal {

IdpRepository::IdpRepository(ConnectionPool& cpPool,
                             const dns::security::CryptoService& csService)
    : _cpPool(cpPool), _csService(csService) {}

IdpRepository::~IdpRepository() = default;

int64_t IdpRepository::create(const std::string& sName, const std::string& sType,
                              const nlohmann::json& jConfig,
                              const std::string& sPlaintextSecret,
                              const nlohmann::json& jGroupMappings,
                              int64_t iDefaultGroupId) {
  std::string sEncryptedSecret;
  if (!sPlaintextSecret.empty()) {
    sEncryptedSecret = _csService.encrypt(sPlaintextSecret);
  }

  std::string sConfigText = jConfig.dump();
  std::string sMappingsText = jGroupMappings.is_null() ? std::string{} : jGroupMappings.dump();

  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);

  try {
    auto result = txn.exec(
        "INSERT INTO identity_providers (name, type, config, encrypted_secret, "
        "group_mappings, default_group_id) "
        "VALUES ($1, $2, $3::jsonb, $4, "
        "CASE WHEN $5 = '' THEN NULL ELSE $5::jsonb END, "
        "NULLIF($6, 0)) RETURNING id",
        pqxx::params{sName, sType, sConfigText,
                     sEncryptedSecret.empty() ? std::optional<std::string>{} : sEncryptedSecret,
                     sMappingsText, iDefaultGroupId});
    txn.commit();
    return result.one_row()[0].as<int64_t>();
  } catch (const pqxx::unique_violation&) {
    throw common::ConflictError("IDP_EXISTS",
                                "Identity provider with name '" + sName + "' already exists");
  }
}

std::optional<IdpRow> IdpRepository::findById(int64_t iId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT id, name, type, is_enabled, config::text, encrypted_secret, "
      "COALESCE(group_mappings::text, ''), COALESCE(default_group_id, 0), "
      "to_char(created_at, 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), "
      "to_char(updated_at, 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') "
      "FROM identity_providers WHERE id = $1",
      pqxx::params{iId});
  txn.commit();

  if (result.empty()) return std::nullopt;
  return mapRow(result[0], true);
}

std::vector<IdpRow> IdpRepository::listAll() {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT id, name, type, is_enabled, config::text, '' AS encrypted_secret, "
      "COALESCE(group_mappings::text, ''), COALESCE(default_group_id, 0), "
      "to_char(created_at, 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), "
      "to_char(updated_at, 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') "
      "FROM identity_providers ORDER BY id");
  txn.commit();

  std::vector<IdpRow> vRows;
  vRows.reserve(result.size());
  for (const auto& row : result) {
    vRows.push_back(mapRow(row, false));
  }
  return vRows;
}

std::vector<IdpRow> IdpRepository::listEnabled() {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT id, name, type, is_enabled, config::text, '' AS encrypted_secret, "
      "COALESCE(group_mappings::text, ''), COALESCE(default_group_id, 0), "
      "to_char(created_at, 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), "
      "to_char(updated_at, 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') "
      "FROM identity_providers WHERE is_enabled = true ORDER BY id");
  txn.commit();

  std::vector<IdpRow> vRows;
  vRows.reserve(result.size());
  for (const auto& row : result) {
    vRows.push_back(mapRow(row, false));
  }
  return vRows;
}

void IdpRepository::update(int64_t iId, const std::string& sName, bool bIsEnabled,
                           const nlohmann::json& jConfig,
                           const std::string& sPlaintextSecret,
                           const nlohmann::json& jGroupMappings,
                           int64_t iDefaultGroupId) {
  std::string sConfigText = jConfig.dump();
  std::string sMappingsText = jGroupMappings.is_null() ? std::string{} : jGroupMappings.dump();

  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);

  pqxx::result result;
  try {
    if (!sPlaintextSecret.empty()) {
      // Update including the secret
      std::string sEncryptedSecret = _csService.encrypt(sPlaintextSecret);
      result = txn.exec(
          "UPDATE identity_providers SET name = $2, is_enabled = $3, "
          "config = $4::jsonb, encrypted_secret = $5, "
          "group_mappings = CASE WHEN $6 = '' THEN NULL ELSE $6::jsonb END, "
          "default_group_id = NULLIF($7, 0), updated_at = now() "
          "WHERE id = $1",
          pqxx::params{iId, sName, bIsEnabled, sConfigText,
                       sEncryptedSecret, sMappingsText, iDefaultGroupId});
    } else {
      // Update without changing the secret
      result = txn.exec(
          "UPDATE identity_providers SET name = $2, is_enabled = $3, "
          "config = $4::jsonb, "
          "group_mappings = CASE WHEN $5 = '' THEN NULL ELSE $5::jsonb END, "
          "default_group_id = NULLIF($6, 0), updated_at = now() "
          "WHERE id = $1",
          pqxx::params{iId, sName, bIsEnabled, sConfigText,
                       sMappingsText, iDefaultGroupId});
    }
    txn.commit();
  } catch (const pqxx::unique_violation&) {
    throw common::ConflictError("IDP_EXISTS",
                                "Identity provider with name '" + sName + "' already exists");
  }

  if (result.affected_rows() == 0) {
    throw common::NotFoundError("IDP_NOT_FOUND",
                                "Identity provider with id " + std::to_string(iId) + " not found");
  }
}

void IdpRepository::deleteIdp(int64_t iId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec("DELETE FROM identity_providers WHERE id = $1",
                         pqxx::params{iId});
  txn.commit();

  if (result.affected_rows() == 0) {
    throw common::NotFoundError("IDP_NOT_FOUND",
                                "Identity provider with id " + std::to_string(iId) + " not found");
  }
}

IdpRow IdpRepository::mapRow(const pqxx::row& row, bool bDecryptSecret) const {
  IdpRow ir;
  ir.iId = row[0].as<int64_t>();
  ir.sName = row[1].as<std::string>();
  ir.sType = row[2].as<std::string>();
  ir.bIsEnabled = row[3].as<bool>();

  std::string sConfigText = row[4].as<std::string>("");
  if (!sConfigText.empty()) {
    ir.jConfig = nlohmann::json::parse(sConfigText);
  }

  if (bDecryptSecret) {
    std::string sEncSecret = row[5].as<std::string>("");
    if (!sEncSecret.empty()) {
      ir.sDecryptedSecret = _csService.decrypt(sEncSecret);
    }
  }

  std::string sMappingsText = row[6].as<std::string>("");
  if (!sMappingsText.empty()) {
    ir.jGroupMappings = nlohmann::json::parse(sMappingsText);
  }

  ir.iDefaultGroupId = row[7].as<int64_t>(0);
  ir.sCreatedAt = row[8].as<std::string>("");
  ir.sUpdatedAt = row[9].as<std::string>("");

  return ir;
}

}  // namespace dns::dal
