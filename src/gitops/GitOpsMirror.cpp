#include "gitops/GitOpsMirror.hpp"

#include <stdexcept>

namespace dns::gitops {

GitOpsMirror::GitOpsMirror() = default;
GitOpsMirror::~GitOpsMirror() = default;

void GitOpsMirror::initialize(const std::string& /*sRemoteUrl*/,
                              const std::string& /*sLocalPath*/) {
  throw std::runtime_error{"not implemented"};
}

void GitOpsMirror::commit(int64_t /*iZoneId*/, const std::string& /*sActorIdentity*/) {
  throw std::runtime_error{"not implemented"};
}

void GitOpsMirror::pull() { throw std::runtime_error{"not implemented"}; }

void GitOpsMirror::writeZoneSnapshot(int64_t /*iZoneId*/) {
  throw std::runtime_error{"not implemented"};
}

void GitOpsMirror::gitAddCommitPush(const std::string& /*sMessage*/) {
  throw std::runtime_error{"not implemented"};
}

}  // namespace dns::gitops
