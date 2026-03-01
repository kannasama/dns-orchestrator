#include "security/SamlReplayCache.hpp"

#include <algorithm>

namespace dns::security {

SamlReplayCache::SamlReplayCache() = default;
SamlReplayCache::~SamlReplayCache() = default;

bool SamlReplayCache::checkAndInsert(
    const std::string& sAssertionId,
    std::chrono::system_clock::time_point tpNotOnOrAfter) {
  std::lock_guard<std::mutex> lock(_mtx);

  evictExpired();

  auto it = _mCache.find(sAssertionId);
  if (it != _mCache.end()) {
    return false;  // replay detected
  }

  _mCache.emplace(sAssertionId, tpNotOnOrAfter);
  return true;
}

void SamlReplayCache::evictExpired() {
  auto tpNow = std::chrono::system_clock::now();
  for (auto it = _mCache.begin(); it != _mCache.end();) {
    if (it->second < tpNow) {
      it = _mCache.erase(it);
    } else {
      ++it;
    }
  }
}

}  // namespace dns::security
