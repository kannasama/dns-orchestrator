#include "core/ThreadPool.hpp"

#include <stdexcept>

namespace dns::core {

ThreadPool::ThreadPool(int /*iSize*/) { throw std::runtime_error{"not implemented"}; }
ThreadPool::~ThreadPool() = default;

void ThreadPool::shutdown() { throw std::runtime_error{"not implemented"}; }

}  // namespace dns::core
