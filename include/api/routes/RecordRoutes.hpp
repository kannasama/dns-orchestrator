#pragma once

namespace dns::api::routes {

/// Handlers for /api/v1/zones/{id}/records and preview/push
class RecordRoutes {
 public:
  RecordRoutes();
  ~RecordRoutes();

  void registerRoutes();
};

}  // namespace dns::api::routes
