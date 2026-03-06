#include "dal/ProviderRepository.hpp"

#include "common/Errors.hpp"
#include "dal/ConnectionPool.hpp"
#include "security/CryptoService.hpp"

#include <pqxx/pqxx>

namespace dns::dal {

ProviderRepository::ProviderRepository(ConnectionPool& cpPool,
                                       const dns::security::CryptoService& csService)
    : _cpPool(cpPool), _csService(csService) {}

ProviderRepository::~ProviderRepository() = default;

int64_t ProviderRepository::create(const std::string& sName, const std::string& sType,
                                   const std::string& sApiEndpoint,
                                   const std::string& sPlaintextToken,
                                   const nlohmann::json& jConfig) {
  std::string sEncryptedToken = _csService.encrypt(sPlaintextToken);
  std::string sEncryptedConfig =
      jConfig.empty() ? std::string{} : _csService.encrypt(jConfig.dump());

  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);

  try {
    auto result = txn.exec(
        "INSERT INTO providers (name, type, api_endpoint, encrypted_token, encrypted_config) "
        "VALUES ($1, $2::provider_type, $3, $4, $5) RETURNING id",
        pqxx::params{sName, sType, sApiEndpoint, sEncryptedToken, sEncryptedConfig});
    txn.commit();
    return result.one_row()[0].as<int64_t>();
  } catch (const pqxx::unique_violation&) {
    throw common::ConflictError("PROVIDER_EXISTS",
                                "Provider with name '" + sName + "' already exists");
  }
}

std::vector<ProviderRow> ProviderRepository::listAll() {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT id, name, type::text, api_endpoint, encrypted_token, "
      "EXTRACT(EPOCH FROM created_at)::bigint, "
      "EXTRACT(EPOCH FROM updated_at)::bigint, "
      "encrypted_config "
      "FROM providers ORDER BY id");
  txn.commit();

  std::vector<ProviderRow> vRows;
  vRows.reserve(result.size());
  for (const auto& row : result) {
    vRows.push_back(mapRow(row));
  }
  return vRows;
}

std::optional<ProviderRow> ProviderRepository::findById(int64_t iId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT id, name, type::text, api_endpoint, encrypted_token, "
      "EXTRACT(EPOCH FROM created_at)::bigint, "
      "EXTRACT(EPOCH FROM updated_at)::bigint, "
      "encrypted_config "
      "FROM providers WHERE id = $1",
      pqxx::params{iId});
  txn.commit();

  if (result.empty()) return std::nullopt;
  return mapRow(result[0]);
}

void ProviderRepository::update(int64_t iId, const std::string& sName,
                                const std::string& sApiEndpoint,
                                const std::optional<std::string>& oPlaintextToken,
                                const std::optional<nlohmann::json>& oConfig) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);

  // Build SET clauses dynamically based on which optional fields are provided.
  std::string sSql = "UPDATE providers SET name = $2, api_endpoint = $3, "
                     "updated_at = NOW()";
  int iNextParam = 4;
  std::vector<std::string> vEncrypted;  // keep encrypted strings alive

  if (oPlaintextToken.has_value()) {
    vEncrypted.push_back(_csService.encrypt(*oPlaintextToken));
    sSql += ", encrypted_token = $" + std::to_string(iNextParam++);
  }
  if (oConfig.has_value()) {
    vEncrypted.push_back(
        oConfig->empty() ? std::string{} : _csService.encrypt(oConfig->dump()));
    sSql += ", encrypted_config = $" + std::to_string(iNextParam++);
  }
  sSql += " WHERE id = $1";

  pqxx::result result;
  try {
    pqxx::params params;
    params.append(iId);
    params.append(sName);
    params.append(sApiEndpoint);
    for (const auto& s : vEncrypted) {
      params.append(s);
    }
    result = txn.exec(sSql, params);
    txn.commit();
  } catch (const pqxx::unique_violation&) {
    throw common::ConflictError("PROVIDER_EXISTS",
                                "Provider with name '" + sName + "' already exists");
  }

  if (result.affected_rows() == 0) {
    throw common::NotFoundError("PROVIDER_NOT_FOUND",
                                "Provider with id " + std::to_string(iId) + " not found");
  }
}

void ProviderRepository::deleteById(int64_t iId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec("DELETE FROM providers WHERE id = $1", pqxx::params{iId});
  txn.commit();

  if (result.affected_rows() == 0) {
    throw common::NotFoundError("PROVIDER_NOT_FOUND",
                                "Provider with id " + std::to_string(iId) + " not found");
  }
}

ProviderRow ProviderRepository::mapRow(const pqxx::row& row) const {
  ProviderRow pr;
  pr.iId = row[0].as<int64_t>();
  pr.sName = row[1].as<std::string>();
  pr.sType = row[2].as<std::string>();
  pr.sApiEndpoint = row[3].as<std::string>();
  pr.sDecryptedToken = _csService.decrypt(row[4].as<std::string>());
  pr.tpCreatedAt = std::chrono::system_clock::time_point(
      std::chrono::seconds(row[5].as<int64_t>()));
  pr.tpUpdatedAt = std::chrono::system_clock::time_point(
      std::chrono::seconds(row[6].as<int64_t>()));

  std::string sEncConfig = row[7].as<std::string>("");
  if (!sEncConfig.empty()) {
    pr.jConfig = nlohmann::json::parse(_csService.decrypt(sEncConfig));
  }
  return pr;
}

}  // namespace dns::dal
