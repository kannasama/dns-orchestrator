#include "dal/SessionRepository.hpp"
#include "dal/ConnectionPool.hpp"

#include <stdexcept>

namespace dns::dal {

SessionRepository::SessionRepository(ConnectionPool& cpPool) : _cpPool(cpPool) {}
SessionRepository::~SessionRepository() = default;

void SessionRepository::create(int64_t /*iUserId*/, const std::string& /*sTokenHash*/,
                               int /*iSlidingTtlSeconds*/, int /*iAbsoluteTtlSeconds*/) {
  throw std::runtime_error{"not implemented"};
}

void SessionRepository::touch(const std::string& /*sTokenHash*/, int /*iSlidingTtl*/,
                              int /*iAbsoluteTtl*/) {
  throw std::runtime_error{"not implemented"};
}

bool SessionRepository::exists(const std::string& /*sTokenHash*/) {
  throw std::runtime_error{"not implemented"};
}

bool SessionRepository::isValid(const std::string& /*sTokenHash*/) {
  throw std::runtime_error{"not implemented"};
}

void SessionRepository::deleteByHash(const std::string& /*sTokenHash*/) {
  throw std::runtime_error{"not implemented"};
}

int SessionRepository::pruneExpired() { throw std::runtime_error{"not implemented"}; }

}  // namespace dns::dal
