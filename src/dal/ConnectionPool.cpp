#include "dal/ConnectionPool.hpp"

#include "common/Logger.hpp"

#include <chrono>
#include <stdexcept>

namespace dns::dal {

// ── ConnectionGuard ────────────────────────────────────────────────────────

ConnectionGuard::ConnectionGuard(ConnectionPool& cpPool,
                                 std::shared_ptr<pqxx::connection> spConn)
    : _pPool(&cpPool), _spConn(std::move(spConn)) {}

ConnectionGuard::~ConnectionGuard() {
  if (_spConn && _pPool) {
    _pPool->returnConnection(std::move(_spConn));
  }
}

ConnectionGuard::ConnectionGuard(ConnectionGuard&& other) noexcept
    : _pPool(other._pPool), _spConn(std::move(other._spConn)) {
  other._pPool = nullptr;
}

ConnectionGuard& ConnectionGuard::operator=(ConnectionGuard&& other) noexcept {
  if (this != &other) {
    if (_spConn && _pPool) {
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
  auto spLog = common::Logger::get();
  spLog->info("Initializing connection pool: size={}, url={}",
              _iPoolSize, _sDbUrl.substr(0, _sDbUrl.find('@')));

  _vAvailable.reserve(static_cast<size_t>(_iPoolSize));
  for (int i = 0; i < _iPoolSize; ++i) {
    auto spConn = std::make_shared<pqxx::connection>(_sDbUrl);
    if (!spConn->is_open()) {
      throw std::runtime_error("Failed to open database connection " + std::to_string(i + 1));
    }
    _vAvailable.push_back(std::move(spConn));
  }

  spLog->info("Connection pool ready: {} connections established", _iPoolSize);
}

ConnectionPool::~ConnectionPool() {
  std::lock_guard<std::mutex> lock(_mtx);
  _vAvailable.clear();
}

ConnectionGuard ConnectionPool::checkout() {
  std::unique_lock<std::mutex> lock(_mtx);

  // Wait up to 30 seconds for a connection to become available
  const auto bAvailable = _cv.wait_for(lock, std::chrono::seconds(30), [this] {
    return !_vAvailable.empty();
  });

  if (!bAvailable) {
    throw std::runtime_error("Connection pool exhausted: timeout waiting for available connection");
  }

  auto spConn = std::move(_vAvailable.back());
  _vAvailable.pop_back();

  // Validate connection with a lightweight query
  if (!validate(*spConn)) {
    common::Logger::get()->warn("Stale connection detected, reconnecting");
    spConn = std::make_shared<pqxx::connection>(_sDbUrl);
    if (!spConn->is_open()) {
      throw std::runtime_error("Failed to reconnect to database");
    }
  }

  return ConnectionGuard(*this, std::move(spConn));
}

void ConnectionPool::returnConnection(std::shared_ptr<pqxx::connection> spConn) {
  std::lock_guard<std::mutex> lock(_mtx);
  _vAvailable.push_back(std::move(spConn));
  _cv.notify_one();
}

bool ConnectionPool::validate(pqxx::connection& conn) {
  try {
    pqxx::nontransaction ntx(conn);
    ntx.exec("SELECT 1").one_row();
    return true;
  } catch (...) {
    return false;
  }
}

}  // namespace dns::dal
