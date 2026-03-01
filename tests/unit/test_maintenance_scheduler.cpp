#include "core/MaintenanceScheduler.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <thread>

using dns::core::MaintenanceScheduler;
using namespace std::chrono_literals;

TEST(MaintenanceSchedulerTest, ScheduledTaskExecutes) {
  MaintenanceScheduler ms;
  std::atomic<int> iCount{0};

  ms.schedule("test-task", 1s, [&iCount]() { iCount.fetch_add(1); });
  ms.start();

  // Wait enough for at least one execution
  std::this_thread::sleep_for(1500ms);
  ms.stop();

  EXPECT_GE(iCount.load(), 1);
}

TEST(MaintenanceSchedulerTest, MultipleTasksExecuteIndependently) {
  MaintenanceScheduler ms;
  std::atomic<int> iCountA{0};
  std::atomic<int> iCountB{0};

  ms.schedule("task-a", 1s, [&iCountA]() { iCountA.fetch_add(1); });
  ms.schedule("task-b", 1s, [&iCountB]() { iCountB.fetch_add(1); });
  ms.start();

  std::this_thread::sleep_for(1500ms);
  ms.stop();

  EXPECT_GE(iCountA.load(), 1);
  EXPECT_GE(iCountB.load(), 1);
}

TEST(MaintenanceSchedulerTest, StopIsIdempotent) {
  MaintenanceScheduler ms;
  std::atomic<int> iCount{0};

  ms.schedule("task", 1s, [&iCount]() { iCount.fetch_add(1); });
  ms.start();
  ms.stop();
  ms.stop();  // second stop should not crash

  SUCCEED();
}

TEST(MaintenanceSchedulerTest, FailingTaskDoesNotCrashScheduler) {
  MaintenanceScheduler ms;
  std::atomic<int> iGoodCount{0};

  ms.schedule("bad-task", 1s, []() { throw std::runtime_error("task failed"); });
  ms.schedule("good-task", 1s, [&iGoodCount]() { iGoodCount.fetch_add(1); });
  ms.start();

  std::this_thread::sleep_for(1500ms);
  ms.stop();

  // Good task should still have run despite bad task throwing
  EXPECT_GE(iGoodCount.load(), 1);
}

TEST(MaintenanceSchedulerTest, DestructorStopsCleanly) {
  std::atomic<int> iCount{0};

  {
    MaintenanceScheduler ms;
    ms.schedule("task", 1s, [&iCount]() { iCount.fetch_add(1); });
    ms.start();
    std::this_thread::sleep_for(500ms);
  }
  // Destructor should stop cleanly without hanging or crashing
  SUCCEED();
}
