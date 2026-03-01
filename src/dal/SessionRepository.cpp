#include "dal/SessionRepository.hpp"

#include "dal/ConnectionPool.hpp"

#include <pqxx/pqxx>

namespace dns::dal {

SessionRepository::SessionRepository(ConnectionPool& cpPool) : _cpPool(cpPool) {}
SessionRepository::~SessionRepository() = default;

void SessionRepository::create(int64_t iUserId, const std::string& sTokenHash,
                               int iSlidingTtlSeconds, int iAbsoluteTtlSeconds) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  txn.exec(
      "INSERT INTO sessions (user_id, token_hash, expires_at, absolute_expires_at) "
      "VALUES ($1, $2, NOW() + make_interval(secs => $3), "
      "NOW() + make_interval(secs => $4))",
      pqxx::params{iUserId, sTokenHash, iSlidingTtlSeconds, iAbsoluteTtlSeconds});
  txn.commit();
}

void SessionRepository::touch(const std::string& sTokenHash, int iSlidingTtl,
                              int /*iAbsoluteTtl*/) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  // Extend expires_at by sliding TTL, clamped to absolute_expires_at
  txn.exec(
      "UPDATE sessions SET "
      "last_seen_at = NOW(), "
      "expires_at = LEAST(NOW() + make_interval(secs => $2), absolute_expires_at) "
      "WHERE token_hash = $1",
      pqxx::params{sTokenHash, iSlidingTtl});
  txn.commit();
}

bool SessionRepository::exists(const std::string& sTokenHash) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT 1 FROM sessions WHERE token_hash = $1",
      pqxx::params{sTokenHash});
  txn.commit();
  return !result.empty();
}

bool SessionRepository::isValid(const std::string& sTokenHash) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "SELECT 1 FROM sessions s "
      "JOIN users u ON u.id = s.user_id "
      "WHERE s.token_hash = $1 "
      "AND s.expires_at > NOW() "
      "AND s.absolute_expires_at > NOW() "
      "AND u.is_active = TRUE",
      pqxx::params{sTokenHash});
  txn.commit();
  return !result.empty();
}

void SessionRepository::deleteByHash(const std::string& sTokenHash) {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  txn.exec("DELETE FROM sessions WHERE token_hash = $1",
           pqxx::params{sTokenHash});
  txn.commit();
}

int SessionRepository::pruneExpired() {
  auto cg = _cpPool.checkout();
  pqxx::work txn(*cg);
  auto result = txn.exec(
      "DELETE FROM sessions WHERE expires_at < NOW() OR absolute_expires_at < NOW()");
  txn.commit();
  return static_cast<int>(result.affected_rows());
}

}  // namespace dns::dal
