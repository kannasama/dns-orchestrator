#include "core/MaintenanceScheduler.hpp"

#include "common/Logger.hpp"

#include <algorithm>

namespace dns::core {

MaintenanceScheduler::MaintenanceScheduler() = default;

MaintenanceScheduler::~MaintenanceScheduler() {
  stop();
}

void MaintenanceScheduler::schedule(const std::string& sName,
                                    std::chrono::seconds durInterval,
                                    std::function<void()> fnTask) {
  _vTasks.push_back(Task{
      sName,
      durInterval,
      std::move(fnTask),
      std::chrono::steady_clock::now()  // run immediately on first pass
  });
}

void MaintenanceScheduler::start() {
  std::lock_guard<std::mutex> lock(_mtx);
  if (_bRunning) return;
  _bRunning = true;

  _thread = std::jthread([this](std::stop_token stToken) {
    auto spLog = dns::common::Logger::get();

    while (!stToken.stop_requested()) {
      auto tpNow = std::chrono::steady_clock::now();

      for (auto& task : _vTasks) {
        if (tpNow >= task.tpNextRun) {
          try {
            task.fn();
          } catch (const std::exception& ex) {
            if (spLog) {
              spLog->error("MaintenanceScheduler: task '{}' failed: {}", task.sName, ex.what());
            }
          } catch (...) {
            if (spLog) {
              spLog->error("MaintenanceScheduler: task '{}' failed with unknown error", task.sName);
            }
          }
          task.tpNextRun = std::chrono::steady_clock::now() + task.durInterval;
        }
      }

      // Find the next scheduled run time
      auto tpNextWake = std::chrono::steady_clock::now() + std::chrono::hours(1);
      for (const auto& task : _vTasks) {
        tpNextWake = std::min(tpNextWake, task.tpNextRun);
      }

      // Sleep until next task is due, or until stop is requested
      std::unique_lock<std::mutex> ulock(_mtx);
      _cv.wait_until(ulock, tpNextWake, [&stToken]() {
        return stToken.stop_requested();
      });
    }
  });
}

void MaintenanceScheduler::stop() {
  {
    std::lock_guard<std::mutex> lock(_mtx);
    if (!_bRunning) return;
    _bRunning = false;
  }

  _thread.request_stop();
  _cv.notify_all();

  if (_thread.joinable()) {
    _thread.join();
  }
}

}  // namespace dns::core
