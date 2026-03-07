#pragma once

#include <memory>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "providers/IProvider.hpp"

namespace httplib {
class Client;
}

namespace dns::providers {

/// DigitalOcean API v2 /domains provider implementation.
class DigitalOceanProvider : public IProvider {
 public:
  DigitalOceanProvider(std::string sApiEndpoint, std::string sToken,
                       nlohmann::json jConfig = nlohmann::json::object());
  ~DigitalOceanProvider() override;

  std::string name() const override;
  common::HealthStatus testConnectivity() override;
  std::vector<common::DnsRecord> listRecords(const std::string& sZoneName) override;
  common::PushResult createRecord(const std::string& sZoneName,
                                  const common::DnsRecord& drRecord) override;
  common::PushResult updateRecord(const std::string& sZoneName,
                                  const common::DnsRecord& drRecord) override;
  bool deleteRecord(const std::string& sZoneName,
                    const std::string& sProviderRecordId) override;

  /// Parse DNS records from DigitalOcean /domains/{domain}/records response.
  /// Converts relative names to FQDNs using the zone name.
  /// Public for unit testing.
  static std::vector<common::DnsRecord> parseRecordsResponse(const std::string& sJson,
                                                              const std::string& sZoneName);

  /// Convert DigitalOcean relative record name to FQDN.
  /// "@" → zoneName, "www" → "www.zoneName"
  static std::string toFqdn(const std::string& sName, const std::string& sZoneName);

  /// Convert FQDN to DigitalOcean relative record name.
  /// "example.com" → "@", "www.example.com" → "www"
  static std::string toRelative(const std::string& sFqdn, const std::string& sZoneName);

 private:
  std::string _sApiEndpoint;
  std::string _sToken;
  nlohmann::json _jConfig;
  std::unique_ptr<httplib::Client> _upClient;
};

}  // namespace dns::providers
