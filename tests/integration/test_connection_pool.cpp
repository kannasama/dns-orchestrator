#include "dal/ConnectionPool.hpp"

#include "common/Logger.hpp"

#include <gtest/gtest.h>

#include <cstdlib>
#include <string>
#include <thread>
#include <vector>

using dns::dal::ConnectionPool;
using dns::dal::ConnectionGuard;

namespace {

std::string getDbUrl() {
  const char* pUrl = std::getenv("DNS_DB_URL");
  return pUrl ? std::string(pUrl) : std::string{};
}

}  // namespace

class ConnectionPoolTest : public ::testing::Test {
 protected:
  void SetUp() override {
    _sDbUrl = getDbUrl();
    if (_sDbUrl.empty()) {
      GTEST_SKIP() << "DNS_DB_URL not set — skipping integration test";
    }
    dns::common::Logger::init("warn");
  }

  std::string _sDbUrl;
};

TEST_F(ConnectionPoolTest, CreatesPoolOfRequestedSize) {
  const int iPoolSize = 3;
  ConnectionPool cpPool(_sDbUrl, iPoolSize);
  EXPECT_EQ(cpPool.size(), iPoolSize);
}

TEST_F(ConnectionPoolTest, ConnectionGuardRaiiReturnsOnScopeExit) {
  ConnectionPool cpPool(_sDbUrl, 2);

  {
    auto cg1 = cpPool.checkout();
    auto cg2 = cpPool.checkout();
    // Both connections checked out — pool exhausted (would block on a 3rd)

    // Can execute queries through the guard
    pqxx::nontransaction ntx(*cg1);
    auto result = ntx.exec("SELECT 1 AS val");
    EXPECT_EQ(result.one_row()[0].as<int>(), 1);
  }
  // Connections returned — can check out again
  auto cg3 = cpPool.checkout();
  pqxx::nontransaction ntx(*cg3);
  auto result = ntx.exec("SELECT 1 AS val");
  EXPECT_EQ(result.one_row()[0].as<int>(), 1);
}

TEST_F(ConnectionPoolTest, SelectOneSucceedsOnEachConnection) {
  const int iPoolSize = 3;
  ConnectionPool cpPool(_sDbUrl, iPoolSize);

  for (int i = 0; i < iPoolSize; ++i) {
    auto cgConn = cpPool.checkout();
    pqxx::nontransaction ntx(*cgConn);
    auto result = ntx.exec("SELECT 1 AS val");
    EXPECT_EQ(result.one_row()[0].as<int>(), 1);
  }
}

TEST_F(ConnectionPoolTest, ConcurrentCheckoutsFromMultipleThreads) {
  const int iPoolSize = 4;
  const int iThreadCount = 8;
  ConnectionPool cpPool(_sDbUrl, iPoolSize);

  std::vector<std::thread> vThreads;
  std::atomic<int> iSuccessCount{0};

  for (int i = 0; i < iThreadCount; ++i) {
    vThreads.emplace_back([&cpPool, &iSuccessCount]() {
      try {
        auto cgConn = cpPool.checkout();
        pqxx::nontransaction ntx(*cgConn);
        auto result = ntx.exec("SELECT 1 AS val");
        if (result.one_row()[0].as<int>() == 1) {
          iSuccessCount.fetch_add(1);
        }
        // Simulate some work
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
      } catch (...) {
        // Connection checkout timeout or error
      }
    });
  }

  for (auto& t : vThreads) {
    t.join();
  }

  // All threads should succeed (pool size 4, threads take 10ms each)
  EXPECT_EQ(iSuccessCount.load(), iThreadCount);
}
