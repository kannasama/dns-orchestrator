#include "providers/CloudflareProvider.hpp"

#include <stdexcept>

namespace dns::providers {

CloudflareProvider::CloudflareProvider(std::string sApiEndpoint, std::string sToken)
    : _sApiEndpoint(std::move(sApiEndpoint)), _sToken(std::move(sToken)) {}

CloudflareProvider::~CloudflareProvider() = default;

std::string CloudflareProvider::name() const { return "cloudflare"; }

common::HealthStatus CloudflareProvider::testConnectivity() {
  throw std::runtime_error{"not implemented"};
}

std::vector<common::DnsRecord> CloudflareProvider::listRecords(const std::string& /*sZoneName*/) {
  throw std::runtime_error{"not implemented"};
}

common::PushResult CloudflareProvider::createRecord(const std::string& /*sZoneName*/,
                                                    const common::DnsRecord& /*drRecord*/) {
  throw std::runtime_error{"not implemented"};
}

common::PushResult CloudflareProvider::updateRecord(const std::string& /*sZoneName*/,
                                                    const common::DnsRecord& /*drRecord*/) {
  throw std::runtime_error{"not implemented"};
}

bool CloudflareProvider::deleteRecord(const std::string& /*sZoneName*/,
                                      const std::string& /*sProviderRecordId*/) {
  throw std::runtime_error{"not implemented"};
}

}  // namespace dns::providers
