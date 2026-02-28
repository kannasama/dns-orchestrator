#include "dal/ApiKeyRepository.hpp"

#include <stdexcept>

namespace dns::dal {

ApiKeyRepository::ApiKeyRepository() = default;
ApiKeyRepository::~ApiKeyRepository() = default;

void ApiKeyRepository::scheduleDelete(int64_t /*iKeyId*/, int /*iGraceSeconds*/) {
  throw std::runtime_error{"not implemented"};
}

int ApiKeyRepository::pruneScheduled() { throw std::runtime_error{"not implemented"}; }

}  // namespace dns::dal
