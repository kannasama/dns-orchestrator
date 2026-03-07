#include "providers/DigitalOceanProvider.hpp"

#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "common/Types.hpp"

using dns::common::DnsRecord;
using dns::providers::DigitalOceanProvider;

// --- parseRecordsResponse tests ---

TEST(DoParseTest, EmptyRecordList) {
  std::string sJson = R"({
    "domain_records": [],
    "links": {},
    "meta": {"total": 0}
  })";
  auto vRecords = DigitalOceanProvider::parseRecordsResponse(sJson, "example.com");
  EXPECT_TRUE(vRecords.empty());
}

TEST(DoParseTest, SingleARecord) {
  std::string sJson = R"({
    "domain_records": [{
      "id": 12345,
      "type": "A",
      "name": "www",
      "data": "192.168.1.1",
      "ttl": 300,
      "priority": null
    }],
    "links": {},
    "meta": {"total": 1}
  })";
  auto vRecords = DigitalOceanProvider::parseRecordsResponse(sJson, "example.com");
  ASSERT_EQ(vRecords.size(), 1u);
  EXPECT_EQ(vRecords[0].sProviderRecordId, "12345");
  EXPECT_EQ(vRecords[0].sName, "www.example.com");
  EXPECT_EQ(vRecords[0].sType, "A");
  EXPECT_EQ(vRecords[0].uTtl, 300u);
  EXPECT_EQ(vRecords[0].sValue, "192.168.1.1");
}

TEST(DoParseTest, ApexRecord) {
  std::string sJson = R"({
    "domain_records": [{
      "id": 12346,
      "type": "A",
      "name": "@",
      "data": "10.0.0.1",
      "ttl": 1800,
      "priority": null
    }],
    "links": {},
    "meta": {"total": 1}
  })";
  auto vRecords = DigitalOceanProvider::parseRecordsResponse(sJson, "example.com");
  ASSERT_EQ(vRecords.size(), 1u);
  EXPECT_EQ(vRecords[0].sName, "example.com");
}

TEST(DoParseTest, MxRecordWithPriority) {
  std::string sJson = R"({
    "domain_records": [{
      "id": 12347,
      "type": "MX",
      "name": "@",
      "data": "mail.example.com.",
      "ttl": 3600,
      "priority": 10
    }],
    "links": {},
    "meta": {"total": 1}
  })";
  auto vRecords = DigitalOceanProvider::parseRecordsResponse(sJson, "example.com");
  ASSERT_EQ(vRecords.size(), 1u);
  EXPECT_EQ(vRecords[0].sType, "MX");
  EXPECT_EQ(vRecords[0].iPriority, 10);
  EXPECT_EQ(vRecords[0].sValue, "mail.example.com.");
}

TEST(DoParseTest, CnameRecord) {
  std::string sJson = R"({
    "domain_records": [{
      "id": 12348,
      "type": "CNAME",
      "name": "blog",
      "data": "example.com.",
      "ttl": 300,
      "priority": null
    }],
    "links": {},
    "meta": {"total": 1}
  })";
  auto vRecords = DigitalOceanProvider::parseRecordsResponse(sJson, "example.com");
  ASSERT_EQ(vRecords.size(), 1u);
  EXPECT_EQ(vRecords[0].sName, "blog.example.com");
  EXPECT_EQ(vRecords[0].sType, "CNAME");
}

TEST(DoParseTest, MultipleRecords) {
  std::string sJson = R"({
    "domain_records": [
      {"id": 1, "type": "A", "name": "@", "data": "1.1.1.1", "ttl": 300, "priority": null},
      {"id": 2, "type": "A", "name": "www", "data": "1.1.1.1", "ttl": 300, "priority": null},
      {"id": 3, "type": "MX", "name": "@", "data": "mx.example.com.", "ttl": 3600, "priority": 10}
    ],
    "links": {},
    "meta": {"total": 3}
  })";
  auto vRecords = DigitalOceanProvider::parseRecordsResponse(sJson, "example.com");
  ASSERT_EQ(vRecords.size(), 3u);
}

// --- Name conversion tests ---

TEST(DoNameConversionTest, ToFqdnApex) {
  EXPECT_EQ(DigitalOceanProvider::toFqdn("@", "example.com"), "example.com");
}

TEST(DoNameConversionTest, ToFqdnSubdomain) {
  EXPECT_EQ(DigitalOceanProvider::toFqdn("www", "example.com"), "www.example.com");
}

TEST(DoNameConversionTest, ToFqdnEmpty) {
  EXPECT_EQ(DigitalOceanProvider::toFqdn("", "example.com"), "example.com");
}

TEST(DoNameConversionTest, ToRelativeApex) {
  EXPECT_EQ(DigitalOceanProvider::toRelative("example.com", "example.com"), "@");
}

TEST(DoNameConversionTest, ToRelativeSubdomain) {
  EXPECT_EQ(DigitalOceanProvider::toRelative("www.example.com", "example.com"), "www");
}

TEST(DoNameConversionTest, ToRelativeDeep) {
  EXPECT_EQ(DigitalOceanProvider::toRelative("a.b.example.com", "example.com"), "a.b");
}
