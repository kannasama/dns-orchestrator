#include "providers/PowerDnsProvider.hpp"

#include <stdexcept>

namespace dns::providers {

PowerDnsProvider::PowerDnsProvider(std::string sApiEndpoint, std::string sToken)
    : _sApiEndpoint(std::move(sApiEndpoint)), _sToken(std::move(sToken)) {}

PowerDnsProvider::~PowerDnsProvider() = default;

std::string PowerDnsProvider::name() const { return "powerdns"; }

common::HealthStatus PowerDnsProvider::testConnectivity() {
  throw std::runtime_error{"not implemented"};
}

std::vector<common::DnsRecord> PowerDnsProvider::listRecords(const std::string& /*sZoneName*/) {
  throw std::runtime_error{"not implemented"};
}

common::PushResult PowerDnsProvider::createRecord(const std::string& /*sZoneName*/,
                                                  const common::DnsRecord& /*drRecord*/) {
  throw std::runtime_error{"not implemented"};
}

common::PushResult PowerDnsProvider::updateRecord(const std::string& /*sZoneName*/,
                                                  const common::DnsRecord& /*drRecord*/) {
  throw std::runtime_error{"not implemented"};
}

bool PowerDnsProvider::deleteRecord(const std::string& /*sZoneName*/,
                                    const std::string& /*sProviderRecordId*/) {
  throw std::runtime_error{"not implemented"};
}

}  // namespace dns::providers
