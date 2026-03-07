#pragma once

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>

#include "providers/IProvider.hpp"

namespace httplib {
class Client;
}

namespace dns::providers {

/// Cloudflare API v4 provider implementation.
class CloudflareProvider : public IProvider {
 public:
  CloudflareProvider(std::string sApiEndpoint, std::string sToken,
                     nlohmann::json jConfig = nlohmann::json::object());
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

  /// Parse zone ID from Cloudflare /zones?name= response.
  /// Public for unit testing.
  static std::string parseZoneIdResponse(const std::string& sJson,
                                         const std::string& sZoneName);

  /// Parse DNS records from Cloudflare /dns_records response.
  /// Public for unit testing.
  static std::vector<common::DnsRecord> parseRecordsResponse(const std::string& sJson);

  /// Build the JSON body for a create/update record request.
  /// Public for unit testing.
  static nlohmann::json buildRecordBody(const common::DnsRecord& drRecord);

 private:
  std::string _sApiEndpoint;
  std::string _sToken;
  std::string _sAccountId;
  nlohmann::json _jConfig;
  std::unique_ptr<httplib::Client> _upClient;

  /// Cached zone name → Cloudflare zone ID map.
  std::unordered_map<std::string, std::string> _mZoneIdCache;

  /// Resolve zone name to Cloudflare zone ID (cached).
  std::string resolveZoneId(const std::string& sZoneName);
};

}  // namespace dns::providers
