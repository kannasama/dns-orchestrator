#pragma once

#include <string>
#include <vector>

#include "providers/IProvider.hpp"

namespace dns::providers {

/// Cloudflare API v4 provider implementation.
class CloudflareProvider : public IProvider {
 public:
  CloudflareProvider(std::string sApiEndpoint, std::string sToken);
  ~CloudflareProvider() override;

  std::string name() const override;
  common::HealthStatus testConnectivity() override;
  std::vector<common::DnsRecord> listRecords(const std::string& sZoneName) override;
  common::PushResult createRecord(const std::string& sZoneName,
                                  const common::DnsRecord& drRecord) override;
  common::PushResult updateRecord(const std::string& sZoneName,
                                  const common::DnsRecord& drRecord) override;
  bool deleteRecord(const std::string& sZoneName,
                    const std::string& sProviderRecordId) override;

 private:
  std::string _sApiEndpoint;
  std::string _sToken;
};

}  // namespace dns::providers
