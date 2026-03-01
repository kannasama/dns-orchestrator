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
                                   const std::string& sRawToken) {
  std::string sEncrypted = _csService.encrypt(sRawToken);
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  try {
    auto result = txn.exec(
        "INSERT INTO providers (name, type, api_endpoint, encrypted_token) "
        "VALUES ($1, $2::provider_type, $3, $4) RETURNING id",
        pqxx::params{sName, sType, sApiEndpoint, sEncrypted});
    txn.commit();
    return result.one_row()[0].as<int64_t>();
  } catch (const pqxx::unique_violation&) {
    throw common::ConflictError("duplicate_provider",
                                "Provider with name '" + sName + "' already exists");
  }
}

std::optional<ProviderDetailRow> ProviderRepository::findById(int64_t iProviderId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT id, name, type::text, api_endpoint, encrypted_token, "
      "created_at::text, updated_at::text "
      "FROM providers WHERE id = $1",
      pqxx::params{iProviderId});
  txn.commit();

  if (result.empty()) return std::nullopt;

  auto row = result[0];
  return ProviderDetailRow{
      row[0].as<int64_t>(),
      row[1].as<std::string>(),
      row[2].as<std::string>(),
      row[3].as<std::string>(),
      _csService.decrypt(row[4].as<std::string>()),
      row[5].as<std::string>(),
      row[6].as<std::string>(),
  };
}

std::vector<ProviderRow> ProviderRepository::list() {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT id, name, type::text, api_endpoint, "
      "created_at::text, updated_at::text "
      "FROM providers ORDER BY name");
  txn.commit();

  std::vector<ProviderRow> vRows;
  vRows.reserve(result.size());
  for (const auto& row : result) {
    vRows.push_back({
        row[0].as<int64_t>(),
        row[1].as<std::string>(),
        row[2].as<std::string>(),
        row[3].as<std::string>(),
        row[4].as<std::string>(),
        row[5].as<std::string>(),
    });
  }
  return vRows;
}

void ProviderRepository::update(int64_t iProviderId, const std::string& sName,
                                const std::string& sType,
                                const std::string& sApiEndpoint,
                                const std::string& sRawToken) {
  std::string sEncrypted = _csService.encrypt(sRawToken);
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  try {
    auto result = txn.exec(
        "UPDATE providers SET name = $2, type = $3::provider_type, "
        "api_endpoint = $4, encrypted_token = $5, updated_at = NOW() "
        "WHERE id = $1",
        pqxx::params{iProviderId, sName, sType, sApiEndpoint, sEncrypted});
    txn.commit();
    if (result.affected_rows() == 0) {
      throw common::NotFoundError("provider_not_found", "Provider not found");
    }
  } catch (const pqxx::unique_violation&) {
    throw common::ConflictError("duplicate_provider",
                                "Provider with name '" + sName + "' already exists");
  }
}

void ProviderRepository::deleteById(int64_t iProviderId) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec("DELETE FROM providers WHERE id = $1",
                         pqxx::params{iProviderId});
  txn.commit();
  if (result.affected_rows() == 0) {
    throw common::NotFoundError("provider_not_found", "Provider not found");
  }
}

}  // namespace dns::dal
