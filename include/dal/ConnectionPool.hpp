#pragma once

#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <pqxx/pqxx>

namespace dns::dal {

class ConnectionPool;

/// RAII guard for checked-out database connections.
/// Returns the connection to the pool on destruction.
/// Class abbreviation: cg
class ConnectionGuard {
 public:
  ConnectionGuard(ConnectionPool& cpPool, std::shared_ptr<pqxx::connection> spConn);
  ~ConnectionGuard();

  ConnectionGuard(const ConnectionGuard&) = delete;
  ConnectionGuard& operator=(const ConnectionGuard&) = delete;
  ConnectionGuard(ConnectionGuard&& other) noexcept;
  ConnectionGuard& operator=(ConnectionGuard&& other) noexcept;

  pqxx::connection& operator*();
  pqxx::connection* operator->();

 private:
  ConnectionPool* _pPool;
  std::shared_ptr<pqxx::connection> _spConn;
};

/// Fixed-size pool of pqxx::connection objects.
/// Thread-safe via std::mutex + std::condition_variable.
/// Blocks on exhaustion with configurable timeout.
/// Class abbreviation: cp
class ConnectionPool {
 public:
  ConnectionPool(const std::string& sDbUrl, int iPoolSize);
  ~ConnectionPool();

  /// Check out a connection. Blocks if all connections are in use.
  ConnectionGuard checkout();

  /// Return a connection to the pool. Called by ConnectionGuard destructor.
  void returnConnection(std::shared_ptr<pqxx::connection> spConn);

  /// Get the pool size.
  int size() const { return _iPoolSize; }

 private:
  /// Validate a connection with a lightweight query.
  bool validate(pqxx::connection& conn);

  std::vector<std::shared_ptr<pqxx::connection>> _vAvailable;
  std::mutex _mtx;
  std::condition_variable _cv;
  std::string _sDbUrl;
  int _iPoolSize;
};

}  // namespace dns::dal
