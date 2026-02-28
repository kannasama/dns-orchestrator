#pragma once

namespace dns::dal {

/// Manages the records table (raw templates); upsert for rollback restore.
class RecordRepository {
 public:
  RecordRepository();
  ~RecordRepository();
};

}  // namespace dns::dal
