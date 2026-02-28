#include "security/SamlReplayCache.hpp"

#include <stdexcept>

namespace dns::security {

SamlReplayCache::SamlReplayCache() = default;
SamlReplayCache::~SamlReplayCache() = default;

bool SamlReplayCache::checkAndInsert(
    const std::string& /*sAssertionId*/,
    std::chrono::system_clock::time_point /*tpNotOnOrAfter*/) {
  throw std::runtime_error{"not implemented"};
}

void SamlReplayCache::evictExpired() { throw std::runtime_error{"not implemented"}; }

}  // namespace dns::security
