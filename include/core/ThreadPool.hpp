#pragma once

#include <condition_variable>
#include <functional>
#include <future>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

namespace dns::core {

/// Fixed-size pool of std::jthread workers.
/// Class abbreviation: tp
class ThreadPool {
 public:
  explicit ThreadPool(int iSize = 0);
  ~ThreadPool();

  template <typename F, typename... Args>
  auto submit(F&& fnTask, Args&&... args) -> std::future<decltype(fnTask(args...))>;

  void shutdown();

 private:
  std::vector<std::jthread> _vWorkers;
  std::queue<std::packaged_task<void()>> _qTasks;
  std::mutex _mtx;
  std::condition_variable _cv;
  bool _bStopping = false;
};

}  // namespace dns::core
