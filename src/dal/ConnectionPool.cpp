#include "dal/ConnectionPool.hpp"

#include <stdexcept>

namespace dns::dal {

// ── ConnectionGuard ────────────────────────────────────────────────────────

ConnectionGuard::ConnectionGuard(ConnectionPool& cpPool,
                                 std::shared_ptr<pqxx::connection> spConn)
    : _pPool(&cpPool), _spConn(std::move(spConn)) {}

ConnectionGuard::~ConnectionGuard() {
  if (_spConn) {
    _pPool->returnConnection(std::move(_spConn));
  }
}

ConnectionGuard::ConnectionGuard(ConnectionGuard&& other) noexcept
    : _pPool(other._pPool), _spConn(std::move(other._spConn)) {
  other._pPool = nullptr;
}

ConnectionGuard& ConnectionGuard::operator=(ConnectionGuard&& other) noexcept {
  if (this != &other) {
    if (_spConn) {
      _pPool->returnConnection(std::move(_spConn));
    }
    _pPool = other._pPool;
    _spConn = std::move(other._spConn);
    other._pPool = nullptr;
  }
  return *this;
}

pqxx::connection& ConnectionGuard::operator*() { return *_spConn; }
pqxx::connection* ConnectionGuard::operator->() { return _spConn.get(); }

// ── ConnectionPool ─────────────────────────────────────────────────────────

ConnectionPool::ConnectionPool(const std::string& sDbUrl, int iPoolSize)
    : _sDbUrl(sDbUrl), _iPoolSize(iPoolSize) {
  throw std::runtime_error{"not implemented"};
}

ConnectionPool::~ConnectionPool() = default;

ConnectionGuard ConnectionPool::checkout() { throw std::runtime_error{"not implemented"}; }

void ConnectionPool::returnConnection(std::shared_ptr<pqxx::connection> /*spConn*/) {
  throw std::runtime_error{"not implemented"};
}

}  // namespace dns::dal
