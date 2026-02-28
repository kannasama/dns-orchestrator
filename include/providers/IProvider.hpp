#pragma once

#include <string>
#include <vector>

#include "common/Types.hpp"

namespace dns::providers {

/// Pure abstract interface for all DNS provider integrations.
class IProvider {
 public:
  virtual ~IProvider() = default;

  virtual std::string name() const = 0;
  virtual common::HealthStatus testConnectivity() = 0;
  virtual std::vector<common::DnsRecord> listRecords(const std::string& sZoneName) = 0;
  virtual common::PushResult createRecord(const std::string& sZoneName,
                                          const common::DnsRecord& drRecord) = 0;
  virtual common::PushResult updateRecord(const std::string& sZoneName,
                                          const common::DnsRecord& drRecord) = 0;
  virtual bool deleteRecord(const std::string& sZoneName,
                            const std::string& sProviderRecordId) = 0;
};

}  // namespace dns::providers
