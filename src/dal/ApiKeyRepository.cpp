#include "dal/ApiKeyRepository.hpp"
#include "dal/ConnectionPool.hpp"

#include <stdexcept>

namespace dns::dal {

ApiKeyRepository::ApiKeyRepository(ConnectionPool& cpPool) : _cpPool(cpPool) {}
ApiKeyRepository::~ApiKeyRepository() = default;

int64_t ApiKeyRepository::create(int64_t /*iUserId*/, const std::string& /*sKeyHash*/,
                                 const std::string& /*sDescription*/,
                                 std::optional<std::chrono::system_clock::time_point> /*oExpiresAt*/) {
  throw std::runtime_error{"not implemented"};
}

std::optional<ApiKeyRow> ApiKeyRepository::findByHash(const std::string& /*sKeyHash*/) {
  throw std::runtime_error{"not implemented"};
}

void ApiKeyRepository::scheduleDelete(int64_t /*iKeyId*/, int /*iGraceSeconds*/) {
  throw std::runtime_error{"not implemented"};
}

int ApiKeyRepository::pruneScheduled() { throw std::runtime_error{"not implemented"}; }

}  // namespace dns::dal
