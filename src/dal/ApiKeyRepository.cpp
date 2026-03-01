#include "dal/ApiKeyRepository.hpp"

#include "dal/ConnectionPool.hpp"

#include <pqxx/pqxx>

namespace dns::dal {

ApiKeyRepository::ApiKeyRepository(ConnectionPool& cpPool) : _cpPool(cpPool) {}
ApiKeyRepository::~ApiKeyRepository() = default;

int64_t ApiKeyRepository::create(int64_t iUserId, const std::string& sKeyHash,
                                 const std::string& sDescription,
                                 std::optional<std::chrono::system_clock::time_point> oExpiresAt) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);

  pqxx::result result;
  if (oExpiresAt.has_value()) {
    auto tpExpiry = std::chrono::duration_cast<std::chrono::seconds>(
                        oExpiresAt->time_since_epoch())
                        .count();
    result = txn.exec(
        "INSERT INTO api_keys (user_id, key_hash, description, expires_at) "
        "VALUES ($1, $2, $3, to_timestamp($4)) RETURNING id",
        pqxx::params{iUserId, sKeyHash, sDescription, tpExpiry});
  } else {
    result = txn.exec(
        "INSERT INTO api_keys (user_id, key_hash, description) "
        "VALUES ($1, $2, $3) RETURNING id",
        pqxx::params{iUserId, sKeyHash, sDescription});
  }

  txn.commit();
  return result.one_row()[0].as<int64_t>();
}

std::optional<ApiKeyRow> ApiKeyRepository::findByHash(const std::string& sKeyHash) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT id, user_id, key_hash, COALESCE(description, ''), revoked, "
      "EXTRACT(EPOCH FROM expires_at)::bigint "
      "FROM api_keys WHERE key_hash = $1",
      pqxx::params{sKeyHash});
  txn.commit();

  if (result.empty()) return std::nullopt;

  auto row = result[0];
  ApiKeyRow akRow;
  akRow.iId = row[0].as<int64_t>();
  akRow.iUserId = row[1].as<int64_t>();
  akRow.sKeyHash = row[2].as<std::string>();
  akRow.sDescription = row[3].as<std::string>();
  akRow.bRevoked = row[4].as<bool>();
  if (!row[5].is_null()) {
    akRow.oExpiresAt = std::chrono::system_clock::time_point(
        std::chrono::seconds(row[5].as<int64_t>()));
  }
  return akRow;
}

void ApiKeyRepository::scheduleDelete(int64_t iKeyId, int iGraceSeconds) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  txn.exec(
      "UPDATE api_keys SET delete_after = NOW() + make_interval(secs => $2) "
      "WHERE id = $1",
      pqxx::params{iKeyId, iGraceSeconds});
  txn.commit();
}

int ApiKeyRepository::pruneScheduled() {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "DELETE FROM api_keys WHERE delete_after IS NOT NULL AND delete_after < NOW()");
  txn.commit();
  return static_cast<int>(result.affected_rows());
}

}  // namespace dns::dal
