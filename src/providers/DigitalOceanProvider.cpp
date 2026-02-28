#include "providers/DigitalOceanProvider.hpp"

#include <stdexcept>

namespace dns::providers {

DigitalOceanProvider::DigitalOceanProvider(std::string sApiEndpoint, std::string sToken)
    : _sApiEndpoint(std::move(sApiEndpoint)), _sToken(std::move(sToken)) {}

DigitalOceanProvider::~DigitalOceanProvider() = default;

std::string DigitalOceanProvider::name() const { return "digitalocean"; }

common::HealthStatus DigitalOceanProvider::testConnectivity() {
  throw std::runtime_error{"not implemented"};
}

std::vector<common::DnsRecord> DigitalOceanProvider::listRecords(
    const std::string& /*sZoneName*/) {
  throw std::runtime_error{"not implemented"};
}

common::PushResult DigitalOceanProvider::createRecord(const std::string& /*sZoneName*/,
                                                      const common::DnsRecord& /*drRecord*/) {
  throw std::runtime_error{"not implemented"};
}

common::PushResult DigitalOceanProvider::updateRecord(const std::string& /*sZoneName*/,
                                                      const common::DnsRecord& /*drRecord*/) {
  throw std::runtime_error{"not implemented"};
}

bool DigitalOceanProvider::deleteRecord(const std::string& /*sZoneName*/,
                                        const std::string& /*sProviderRecordId*/) {
  throw std::runtime_error{"not implemented"};
}

}  // namespace dns::providers
