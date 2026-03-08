#include "providers/PowerDnsProvider.hpp"

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "common/Types.hpp"

using dns::common::DnsRecord;
using dns::providers::PowerDnsProvider;

// --- parseZoneResponse tests ---

TEST(PowerDnsParseTest, EmptyRrsets) {
  std::string sJson = R"({"name":"example.com.","rrsets":[]})";
  auto vRecords = PowerDnsProvider::parseZoneResponse(sJson);
  EXPECT_TRUE(vRecords.empty());
}

TEST(PowerDnsParseTest, SingleARecord) {
  std::string sJson = R"({
    "name": "example.com.",
    "rrsets": [{
      "name": "www.example.com.",
      "type": "A",
      "ttl": 300,
      "records": [{"content": "192.168.1.1", "disabled": false}]
    }]
  })";
  auto vRecords = PowerDnsProvider::parseZoneResponse(sJson);
  ASSERT_EQ(vRecords.size(), 1u);
  EXPECT_EQ(vRecords[0].sName, "www.example.com.");
  EXPECT_EQ(vRecords[0].sType, "A");
  EXPECT_EQ(vRecords[0].uTtl, 300u);
  EXPECT_EQ(vRecords[0].sValue, "192.168.1.1");
  EXPECT_EQ(vRecords[0].sProviderRecordId, "www.example.com./A/192.168.1.1");
}

TEST(PowerDnsParseTest, MultipleRecordsInRrset) {
  std::string sJson = R"({
    "name": "example.com.",
    "rrsets": [{
      "name": "example.com.",
      "type": "NS",
      "ttl": 3600,
      "records": [
        {"content": "ns1.example.com.", "disabled": false},
        {"content": "ns2.example.com.", "disabled": false}
      ]
    }]
  })";
  auto vRecords = PowerDnsProvider::parseZoneResponse(sJson);
  ASSERT_EQ(vRecords.size(), 2u);
  EXPECT_EQ(vRecords[0].sValue, "ns1.example.com.");
  EXPECT_EQ(vRecords[1].sValue, "ns2.example.com.");
}

TEST(PowerDnsParseTest, DisabledRecordsSkipped) {
  std::string sJson = R"({
    "name": "example.com.",
    "rrsets": [{
      "name": "www.example.com.",
      "type": "A",
      "ttl": 300,
      "records": [
        {"content": "192.168.1.1", "disabled": false},
        {"content": "192.168.1.2", "disabled": true}
      ]
    }]
  })";
  auto vRecords = PowerDnsProvider::parseZoneResponse(sJson);
  ASSERT_EQ(vRecords.size(), 1u);
  EXPECT_EQ(vRecords[0].sValue, "192.168.1.1");
}

TEST(PowerDnsParseTest, MxRecordWithPriority) {
  std::string sJson = R"({
    "name": "example.com.",
    "rrsets": [{
      "name": "example.com.",
      "type": "MX",
      "ttl": 3600,
      "records": [{"content": "10 mail.example.com.", "disabled": false}]
    }]
  })";
  auto vRecords = PowerDnsProvider::parseZoneResponse(sJson);
  ASSERT_EQ(vRecords.size(), 1u);
  EXPECT_EQ(vRecords[0].sType, "MX");
  EXPECT_EQ(vRecords[0].iPriority, 10);
  EXPECT_EQ(vRecords[0].sValue, "mail.example.com.");
}

TEST(PowerDnsParseTest, SoaRecordIncluded) {
  std::string sJson = R"({
    "name": "example.com.",
    "rrsets": [{
      "name": "example.com.",
      "type": "SOA",
      "ttl": 3600,
      "records": [{"content": "ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400", "disabled": false}]
    }]
  })";
  auto vRecords = PowerDnsProvider::parseZoneResponse(sJson);
  ASSERT_EQ(vRecords.size(), 1u);
  EXPECT_EQ(vRecords[0].sType, "SOA");
}

TEST(PowerDnsParseTest, TxtRecordQuotesStripped) {
  std::string sJson = R"({
    "name": "example.com.",
    "rrsets": [{
      "name": "example.com.",
      "type": "TXT",
      "ttl": 3600,
      "records": [{"content": "\"v=spf1 include:_spf.google.com ~all\"", "disabled": false}]
    }]
  })";
  auto vRecords = PowerDnsProvider::parseZoneResponse(sJson);
  ASSERT_EQ(vRecords.size(), 1u);
  EXPECT_EQ(vRecords[0].sType, "TXT");
  EXPECT_EQ(vRecords[0].sValue, "v=spf1 include:_spf.google.com ~all");
}

TEST(PowerDnsParseTest, TxtRecordWithoutQuotesUnchanged) {
  std::string sJson = R"({
    "name": "example.com.",
    "rrsets": [{
      "name": "example.com.",
      "type": "TXT",
      "ttl": 3600,
      "records": [{"content": "v=spf1 ~all", "disabled": false}]
    }]
  })";
  auto vRecords = PowerDnsProvider::parseZoneResponse(sJson);
  ASSERT_EQ(vRecords.size(), 1u);
  EXPECT_EQ(vRecords[0].sValue, "v=spf1 ~all");
}

// --- makeRecordId / parseRecordId tests ---

TEST(PowerDnsRecordIdTest, MakeAndParse) {
  std::string sId = PowerDnsProvider::makeRecordId("www.example.com.", "A", "1.2.3.4");
  EXPECT_EQ(sId, "www.example.com./A/1.2.3.4");

  std::string sName, sType, sValue;
  ASSERT_TRUE(PowerDnsProvider::parseRecordId(sId, sName, sType, sValue));
  EXPECT_EQ(sName, "www.example.com.");
  EXPECT_EQ(sType, "A");
  EXPECT_EQ(sValue, "1.2.3.4");
}

TEST(PowerDnsRecordIdTest, InvalidFormat) {
  std::string sName, sType, sValue;
  EXPECT_FALSE(PowerDnsProvider::parseRecordId("invalid", sName, sType, sValue));
  EXPECT_FALSE(PowerDnsProvider::parseRecordId("only/one", sName, sType, sValue));
}
