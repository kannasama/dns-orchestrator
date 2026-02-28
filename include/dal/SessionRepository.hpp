#pragma once

#include <string>

namespace dns::dal {

/// Manages the sessions table; touch, exists, deleteByHash, pruneExpired.
class SessionRepository {
 public:
  SessionRepository();
  ~SessionRepository();

  void touch(const std::string& sTokenHash, int iSlidingTtl, int iAbsoluteTtl);
  bool exists(const std::string& sTokenHash);
  void deleteByHash(const std::string& sTokenHash);
  int pruneExpired();
};

}  // namespace dns::dal
