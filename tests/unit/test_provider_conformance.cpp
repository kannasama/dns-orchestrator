#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "common/Types.hpp"
#include "providers/CloudflareProvider.hpp"
#include "providers/DigitalOceanProvider.hpp"
#include "providers/PowerDnsProvider.hpp"

using dns::common::DnsRecord;

// --- Conformance: All providers return consistent DnsRecord structures ---

class ProviderConformanceTest : public ::testing::Test {
 protected:
  // Helper to verify basic DnsRecord invariants
  void verifyRecord(const DnsRecord& dr, const std::string& sProvider) {
    SCOPED_TRACE("Provider: " + sProvider);
    EXPECT_FALSE(dr.sProviderRecordId.empty()) << "Record ID must not be empty";
    EXPECT_FALSE(dr.sName.empty()) << "Record name must not be empty";
    EXPECT_FALSE(dr.sType.empty()) << "Record type must not be empty";
    EXPECT_GT(dr.uTtl, 0u) << "TTL must be positive";
    EXPECT_FALSE(dr.sValue.empty()) << "Record value must not be empty";
  }
};

TEST_F(ProviderConformanceTest, PowerDnsARecord) {
  std::string sJson = R"({
    "name": "example.com.",
    "rrsets": [{
      "name": "www.example.com.",
      "type": "A",
      "ttl": 300,
      "records": [{"content": "1.2.3.4", "disabled": false}]
    }]
  })";
  auto vRecords = dns::providers::PowerDnsProvider::parseZoneResponse(sJson);
  ASSERT_EQ(vRecords.size(), 1u);
  verifyRecord(vRecords[0], "powerdns");
}

TEST_F(ProviderConformanceTest, CloudflareARecord) {
  std::string sJson = R"({
    "success": true,
    "result": [{
      "id": "cf-uuid-1",
      "name": "www.example.com",
      "type": "A",
      "content": "1.2.3.4",
      "ttl": 300,
      "proxied": false
    }],
    "result_info": {"page": 1, "total_pages": 1}
  })";
  auto vRecords = dns::providers::CloudflareProvider::parseRecordsResponse(sJson);
  ASSERT_EQ(vRecords.size(), 1u);
  verifyRecord(vRecords[0], "cloudflare");
}

TEST_F(ProviderConformanceTest, DigitalOceanARecord) {
  std::string sJson = R"({
    "domain_records": [{
      "id": 12345,
      "type": "A",
      "name": "www",
      "data": "1.2.3.4",
      "ttl": 300,
      "priority": null
    }],
    "links": {},
    "meta": {"total": 1}
  })";
  auto vRecords = dns::providers::DigitalOceanProvider::parseRecordsResponse(sJson, "example.com");
  ASSERT_EQ(vRecords.size(), 1u);
  verifyRecord(vRecords[0], "digitalocean");
}

// MX records across all providers
TEST_F(ProviderConformanceTest, AllProvidersMxPriority) {
  // PowerDNS
  {
    std::string sJson = R"({"name":"example.com.","rrsets":[{
      "name":"example.com.","type":"MX","ttl":3600,
      "records":[{"content":"10 mail.example.com.","disabled":false}]
    }]})";
    auto v = dns::providers::PowerDnsProvider::parseZoneResponse(sJson);
    ASSERT_EQ(v.size(), 1u);
    EXPECT_EQ(v[0].iPriority, 10);
    EXPECT_EQ(v[0].sValue, "mail.example.com.");
  }

  // Cloudflare
  {
    std::string sJson = R"({"success":true,"result":[{
      "id":"cf-mx","name":"example.com","type":"MX","content":"mail.example.com",
      "ttl":3600,"priority":10,"proxied":false
    }],"result_info":{"page":1,"total_pages":1}})";
    auto v = dns::providers::CloudflareProvider::parseRecordsResponse(sJson);
    ASSERT_EQ(v.size(), 1u);
    EXPECT_EQ(v[0].iPriority, 10);
    EXPECT_EQ(v[0].sValue, "mail.example.com.");
  }

  // DigitalOcean
  {
    std::string sJson = R"({"domain_records":[{
      "id":100,"type":"MX","name":"@","data":"mail.example.com.",
      "ttl":3600,"priority":10
    }],"links":{},"meta":{"total":1}})";
    auto v = dns::providers::DigitalOceanProvider::parseRecordsResponse(sJson, "example.com");
    ASSERT_EQ(v.size(), 1u);
    EXPECT_EQ(v[0].iPriority, 10);
    EXPECT_EQ(v[0].sValue, "mail.example.com.");
  }
}
