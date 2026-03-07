#include "providers/CloudflareProvider.hpp"

#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "common/Errors.hpp"
#include "common/Types.hpp"

using dns::common::DnsRecord;
using dns::providers::CloudflareProvider;

// --- parseZoneIdResponse tests ---

TEST(CloudflareZoneIdTest, ParsesZoneId) {
  std::string sJson = R"({
    "success": true,
    "result": [{"id": "abc123def456", "name": "example.com"}]
  })";
  auto sId = CloudflareProvider::parseZoneIdResponse(sJson, "example.com");
  EXPECT_EQ(sId, "abc123def456");
}

TEST(CloudflareZoneIdTest, ThrowsWhenZoneNotFound) {
  std::string sJson = R"({
    "success": true,
    "result": []
  })";
  EXPECT_THROW(
      CloudflareProvider::parseZoneIdResponse(sJson, "missing.com"),
      dns::common::ProviderError);
}

TEST(CloudflareZoneIdTest, ThrowsOnApiError) {
  std::string sJson = R"({
    "success": false,
    "errors": [{"code": 9103, "message": "Unknown X-Auth-Key"}]
  })";
  EXPECT_THROW(
      CloudflareProvider::parseZoneIdResponse(sJson, "example.com"),
      dns::common::ProviderError);
}

// --- parseRecordsResponse tests ---

TEST(CloudflareParseTest, EmptyRecordList) {
  std::string sJson = R"({
    "success": true,
    "result": [],
    "result_info": {"page": 1, "total_pages": 1}
  })";
  auto vRecords = CloudflareProvider::parseRecordsResponse(sJson);
  EXPECT_TRUE(vRecords.empty());
}

TEST(CloudflareParseTest, SingleARecord) {
  std::string sJson = R"({
    "success": true,
    "result": [{
      "id": "rec-uuid-1",
      "name": "www.example.com",
      "type": "A",
      "content": "192.168.1.1",
      "ttl": 300,
      "proxied": false
    }],
    "result_info": {"page": 1, "total_pages": 1}
  })";
  auto vRecords = CloudflareProvider::parseRecordsResponse(sJson);
  ASSERT_EQ(vRecords.size(), 1u);
  EXPECT_EQ(vRecords[0].sProviderRecordId, "rec-uuid-1");
  EXPECT_EQ(vRecords[0].sName, "www.example.com");
  EXPECT_EQ(vRecords[0].sType, "A");
  EXPECT_EQ(vRecords[0].uTtl, 300u);
  EXPECT_EQ(vRecords[0].sValue, "192.168.1.1");
  EXPECT_EQ(vRecords[0].iPriority, 0);
}

TEST(CloudflareParseTest, ProxiedARecord) {
  std::string sJson = R"({
    "success": true,
    "result": [{
      "id": "rec-uuid-2",
      "name": "app.example.com",
      "type": "A",
      "content": "10.0.0.1",
      "ttl": 1,
      "proxied": true
    }],
    "result_info": {"page": 1, "total_pages": 1}
  })";
  auto vRecords = CloudflareProvider::parseRecordsResponse(sJson);
  ASSERT_EQ(vRecords.size(), 1u);
  EXPECT_EQ(vRecords[0].uTtl, 1u);
  EXPECT_TRUE(vRecords[0].jProviderMeta.value("proxied", false));
}

TEST(CloudflareParseTest, MxRecordWithPriority) {
  std::string sJson = R"({
    "success": true,
    "result": [{
      "id": "rec-uuid-3",
      "name": "example.com",
      "type": "MX",
      "content": "mail.example.com",
      "ttl": 3600,
      "priority": 10,
      "proxied": false
    }],
    "result_info": {"page": 1, "total_pages": 1}
  })";
  auto vRecords = CloudflareProvider::parseRecordsResponse(sJson);
  ASSERT_EQ(vRecords.size(), 1u);
  EXPECT_EQ(vRecords[0].sType, "MX");
  EXPECT_EQ(vRecords[0].iPriority, 10);
  EXPECT_EQ(vRecords[0].sValue, "mail.example.com");
}

TEST(CloudflareParseTest, MultipleRecords) {
  std::string sJson = R"({
    "success": true,
    "result": [
      {"id": "r1", "name": "example.com", "type": "A", "content": "1.1.1.1", "ttl": 300, "proxied": false},
      {"id": "r2", "name": "example.com", "type": "AAAA", "content": "::1", "ttl": 300, "proxied": false},
      {"id": "r3", "name": "www.example.com", "type": "CNAME", "content": "example.com", "ttl": 300, "proxied": true}
    ],
    "result_info": {"page": 1, "total_pages": 1}
  })";
  auto vRecords = CloudflareProvider::parseRecordsResponse(sJson);
  ASSERT_EQ(vRecords.size(), 3u);
  EXPECT_EQ(vRecords[2].sType, "CNAME");
  EXPECT_TRUE(vRecords[2].jProviderMeta.value("proxied", false));
}

TEST(CloudflareParseTest, TxtRecord) {
  std::string sJson = R"({
    "success": true,
    "result": [{
      "id": "rec-txt-1",
      "name": "example.com",
      "type": "TXT",
      "content": "v=spf1 include:_spf.google.com ~all",
      "ttl": 3600,
      "proxied": false
    }],
    "result_info": {"page": 1, "total_pages": 1}
  })";
  auto vRecords = CloudflareProvider::parseRecordsResponse(sJson);
  ASSERT_EQ(vRecords.size(), 1u);
  EXPECT_EQ(vRecords[0].sType, "TXT");
  EXPECT_EQ(vRecords[0].sValue, "v=spf1 include:_spf.google.com ~all");
}

// --- buildRecordBody tests ---

TEST(CloudflareBuildBodyTest, SimpleARecord) {
  DnsRecord dr;
  dr.sName = "www.example.com";
  dr.sType = "A";
  dr.uTtl = 300;
  dr.sValue = "192.168.1.1";

  auto jBody = CloudflareProvider::buildRecordBody(dr);
  EXPECT_EQ(jBody["name"], "www.example.com");
  EXPECT_EQ(jBody["type"], "A");
  EXPECT_EQ(jBody["content"], "192.168.1.1");
  EXPECT_EQ(jBody["ttl"], 300);
  EXPECT_FALSE(jBody.value("proxied", true));
}

TEST(CloudflareBuildBodyTest, ProxiedRecord) {
  DnsRecord dr;
  dr.sName = "app.example.com";
  dr.sType = "A";
  dr.uTtl = 1;
  dr.sValue = "10.0.0.1";
  dr.jProviderMeta = {{"proxied", true}};

  auto jBody = CloudflareProvider::buildRecordBody(dr);
  EXPECT_TRUE(jBody["proxied"].get<bool>());
  EXPECT_EQ(jBody["ttl"], 1);
}

TEST(CloudflareBuildBodyTest, MxRecordWithPriority) {
  DnsRecord dr;
  dr.sName = "example.com";
  dr.sType = "MX";
  dr.uTtl = 3600;
  dr.sValue = "mail.example.com";
  dr.iPriority = 10;

  auto jBody = CloudflareProvider::buildRecordBody(dr);
  EXPECT_EQ(jBody["priority"], 10);
  EXPECT_EQ(jBody["content"], "mail.example.com");
}
