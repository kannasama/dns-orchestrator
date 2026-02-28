#include "dal/SessionRepository.hpp"

#include <stdexcept>

namespace dns::dal {

SessionRepository::SessionRepository() = default;
SessionRepository::~SessionRepository() = default;

void SessionRepository::touch(const std::string& /*sTokenHash*/, int /*iSlidingTtl*/,
                              int /*iAbsoluteTtl*/) {
  throw std::runtime_error{"not implemented"};
}

bool SessionRepository::exists(const std::string& /*sTokenHash*/) {
  throw std::runtime_error{"not implemented"};
}

void SessionRepository::deleteByHash(const std::string& /*sTokenHash*/) {
  throw std::runtime_error{"not implemented"};
}

int SessionRepository::pruneExpired() { throw std::runtime_error{"not implemented"}; }

}  // namespace dns::dal
