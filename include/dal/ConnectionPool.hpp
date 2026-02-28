#pragma once

#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace pqxx {
class connection;
}

namespace dns::dal {

class ConnectionPool;

/// RAII guard for checked-out database connections.
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
/// Class abbreviation: cp
class ConnectionPool {
 public:
  ConnectionPool(const std::string& sDbUrl, int iPoolSize);
  ~ConnectionPool();

  ConnectionGuard checkout();
  void returnConnection(std::shared_ptr<pqxx::connection> spConn);

 private:
  std::vector<std::shared_ptr<pqxx::connection>> _vConnections;
  std::mutex _mtx;
  std::condition_variable _cv;
  std::string _sDbUrl;
  int _iPoolSize;
};

}  // namespace dns::dal
