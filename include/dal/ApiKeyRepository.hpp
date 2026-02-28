#pragma once

#include <string>

namespace dns::dal {

/// Manages the api_keys table; scheduleDelete, pruneScheduled.
class ApiKeyRepository {
 public:
  ApiKeyRepository();
  ~ApiKeyRepository();

  void scheduleDelete(int64_t iKeyId, int iGraceSeconds);
  int pruneScheduled();
};

}  // namespace dns::dal
