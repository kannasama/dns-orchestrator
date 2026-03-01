#include "security/SamlReplayCache.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <string>

using dns::security::SamlReplayCache;
using Clock = std::chrono::system_clock;

TEST(SamlReplayCacheTest, FirstInsertReturnsTrue) {
  SamlReplayCache cache;
  auto tpExpiry = Clock::now() + std::chrono::minutes(5);
  EXPECT_TRUE(cache.checkAndInsert("assertion-001", tpExpiry));
}

TEST(SamlReplayCacheTest, DuplicateInsertReturnsFalse) {
  SamlReplayCache cache;
  auto tpExpiry = Clock::now() + std::chrono::minutes(5);
  EXPECT_TRUE(cache.checkAndInsert("assertion-002", tpExpiry));
  EXPECT_FALSE(cache.checkAndInsert("assertion-002", tpExpiry));
}

TEST(SamlReplayCacheTest, DifferentIdsAreIndependent) {
  SamlReplayCache cache;
  auto tpExpiry = Clock::now() + std::chrono::minutes(5);
  EXPECT_TRUE(cache.checkAndInsert("id-aaa", tpExpiry));
  EXPECT_TRUE(cache.checkAndInsert("id-bbb", tpExpiry));
}

TEST(SamlReplayCacheTest, ExpiredEntriesAreEvicted) {
  SamlReplayCache cache;
  // Insert with an already-expired timestamp
  auto tpPast = Clock::now() - std::chrono::seconds(1);
  EXPECT_TRUE(cache.checkAndInsert("expired-id", tpPast));

  // Insert a new ID to trigger eviction
  auto tpFuture = Clock::now() + std::chrono::minutes(5);
  EXPECT_TRUE(cache.checkAndInsert("new-id", tpFuture));

  // The expired entry should have been evicted — re-inserting should succeed
  EXPECT_TRUE(cache.checkAndInsert("expired-id", tpFuture));
}

TEST(SamlReplayCacheTest, NonExpiredEntriesAreNotEvicted) {
  SamlReplayCache cache;
  auto tpFuture = Clock::now() + std::chrono::hours(1);
  EXPECT_TRUE(cache.checkAndInsert("valid-id", tpFuture));

  // Trigger eviction with another insert — valid-id should survive
  EXPECT_TRUE(cache.checkAndInsert("other-id", tpFuture));
  EXPECT_FALSE(cache.checkAndInsert("valid-id", tpFuture));
}
