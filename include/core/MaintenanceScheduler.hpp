#pragma once

#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace dns::core {

/// Runs periodic background tasks on configurable intervals.
/// Class abbreviation: ms
class MaintenanceScheduler {
 public:
  MaintenanceScheduler();
  ~MaintenanceScheduler();

  void schedule(const std::string& sName, std::chrono::seconds durInterval,
                std::function<void()> fnTask);
  void start();
  void stop();

 private:
  struct Task {
    std::string sName;
    std::chrono::seconds durInterval;
    std::function<void()> fn;
    std::chrono::steady_clock::time_point tpNextRun;
  };

  std::vector<Task> _vTasks;
  std::jthread _thread;
  std::mutex _mtx;
  std::condition_variable _cv;
  bool _bRunning = false;
};

}  // namespace dns::core
