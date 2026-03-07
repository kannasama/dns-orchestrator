#include "providers/DigitalOceanProvider.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "common/Errors.hpp"
#include "common/Logger.hpp"

namespace dns::providers {

using json = nlohmann::json;

DigitalOceanProvider::DigitalOceanProvider(std::string sApiEndpoint, std::string sToken,
                                             nlohmann::json jConfig)
    : _sApiEndpoint(std::move(sApiEndpoint)),
      _sToken(std::move(sToken)),
      _jConfig(std::move(jConfig)),
      _upClient(std::make_unique<httplib::Client>(_sApiEndpoint)) {
  _upClient->set_default_headers({
      {"Authorization", "Bearer " + _sToken},
      {"Content-Type", "application/json"},
  });
  _upClient->set_connection_timeout(10);
  _upClient->set_read_timeout(30);
}

DigitalOceanProvider::~DigitalOceanProvider() = default;

std::string DigitalOceanProvider::name() const { return "digitalocean"; }

// ---------------------------------------------------------------------------
// Name conversion helpers
// ---------------------------------------------------------------------------

std::string DigitalOceanProvider::toFqdn(const std::string& sName,
                                          const std::string& sZoneName) {
  if (sName == "@" || sName.empty()) return sZoneName;
  return sName + "." + sZoneName;
}

std::string DigitalOceanProvider::toRelative(const std::string& sFqdn,
                                              const std::string& sZoneName) {
  if (sFqdn == sZoneName) return "@";
  std::string sSuffix = "." + sZoneName;
  if (sFqdn.size() > sSuffix.size() &&
      sFqdn.compare(sFqdn.size() - sSuffix.size(), sSuffix.size(), sSuffix) == 0) {
    return sFqdn.substr(0, sFqdn.size() - sSuffix.size());
  }
  return sFqdn;  // Fallback — return as-is
}

// ---------------------------------------------------------------------------
// testConnectivity
// ---------------------------------------------------------------------------

common::HealthStatus DigitalOceanProvider::testConnectivity() {
  auto spLog = common::Logger::get();
  try {
    auto res = _upClient->Get("/v2/account");
    if (!res) {
      spLog->warn("DigitalOcean {}: connection failed", _sApiEndpoint);
      return common::HealthStatus::Unreachable;
    }
    if (res->status == 200) {
      return common::HealthStatus::Ok;
    }
    spLog->warn("DigitalOcean {}: unexpected status {}", _sApiEndpoint, res->status);
    return common::HealthStatus::Degraded;
  } catch (const std::exception& ex) {
    spLog->error("DigitalOcean {}: connectivity test failed: {}", _sApiEndpoint, ex.what());
    return common::HealthStatus::Unreachable;
  }
}

// ---------------------------------------------------------------------------
// listRecords + parseRecordsResponse
// ---------------------------------------------------------------------------

std::vector<common::DnsRecord> DigitalOceanProvider::parseRecordsResponse(
    const std::string& sJson, const std::string& sZoneName) {
  std::vector<common::DnsRecord> vRecords;
  auto jResp = json::parse(sJson);

  for (const auto& jRec : jResp.at("domain_records")) {
    common::DnsRecord dr;
    dr.sProviderRecordId = std::to_string(jRec.at("id").get<int64_t>());
    dr.sName = toFqdn(jRec.at("name").get<std::string>(), sZoneName);
    dr.sType = jRec.at("type").get<std::string>();
    dr.uTtl = jRec.at("ttl").get<uint32_t>();
    dr.sValue = jRec.at("data").get<std::string>();
    // DigitalOcean returns null for priority on non-MX/SRV records
    if (jRec["priority"].is_null()) {
      dr.iPriority = 0;
    } else {
      dr.iPriority = jRec["priority"].get<int>();
    }

    vRecords.push_back(std::move(dr));
  }

  return vRecords;
}

std::vector<common::DnsRecord> DigitalOceanProvider::listRecords(
    const std::string& sZoneName) {
  auto spLog = common::Logger::get();

  std::vector<common::DnsRecord> vAll;
  int iPage = 1;
  bool bHasMore = true;

  while (bHasMore) {
    std::string sPath = "/v2/domains/" + sZoneName +
                        "/records?per_page=200&page=" + std::to_string(iPage);
    auto res = _upClient->Get(sPath);
    if (!res) {
      throw common::ProviderError("DO_UNREACHABLE",
                                  "Failed to connect to DigitalOcean at " + _sApiEndpoint);
    }
    if (res->status != 200) {
      throw common::ProviderError("DO_LIST_FAILED",
                                  "DigitalOcean returned status " + std::to_string(res->status));
    }

    auto jResp = json::parse(res->body);
    auto vPage = parseRecordsResponse(res->body, sZoneName);
    vAll.insert(vAll.end(), vPage.begin(), vPage.end());

    // Check pagination — DigitalOcean uses links.pages.next
    bHasMore = jResp.contains("links") && jResp["links"].contains("pages") &&
               jResp["links"]["pages"].contains("next");
    ++iPage;
  }

  spLog->debug("DigitalOcean: listed {} records for zone {}", vAll.size(), sZoneName);
  return vAll;
}

// ---------------------------------------------------------------------------
// CRUD: createRecord, updateRecord, deleteRecord
// ---------------------------------------------------------------------------

common::PushResult DigitalOceanProvider::createRecord(const std::string& sZoneName,
                                                      const common::DnsRecord& drRecord) {
  auto spLog = common::Logger::get();
  std::string sPath = "/v2/domains/" + sZoneName + "/records";

  json jBody = {
      {"type", drRecord.sType},
      {"name", toRelative(drRecord.sName, sZoneName)},
      {"data", drRecord.sValue},
      {"ttl", drRecord.uTtl},
  };
  if ((drRecord.sType == "MX" || drRecord.sType == "SRV") && drRecord.iPriority > 0) {
    jBody["priority"] = drRecord.iPriority;
  }

  auto res = _upClient->Post(sPath, jBody.dump(), "application/json");
  if (!res) {
    return {false, "", "Failed to connect to DigitalOcean"};
  }
  if (res->status != 201) {
    std::string sError = "DigitalOcean create failed (status " +
                         std::to_string(res->status) + ")";
    try {
      auto jResp = json::parse(res->body);
      sError = jResp.value("message", sError);
    } catch (...) {}
    return {false, "", sError};
  }

  auto jResp = json::parse(res->body);
  std::string sNewId = std::to_string(
      jResp["domain_record"].at("id").get<int64_t>());
  spLog->info("DigitalOcean: created record {} in zone {}", sNewId, sZoneName);
  return {true, sNewId, ""};
}

common::PushResult DigitalOceanProvider::updateRecord(const std::string& sZoneName,
                                                      const common::DnsRecord& drRecord) {
  auto spLog = common::Logger::get();
  std::string sPath = "/v2/domains/" + sZoneName + "/records/" +
                      drRecord.sProviderRecordId;

  json jBody = {
      {"type", drRecord.sType},
      {"name", toRelative(drRecord.sName, sZoneName)},
      {"data", drRecord.sValue},
      {"ttl", drRecord.uTtl},
  };
  if ((drRecord.sType == "MX" || drRecord.sType == "SRV") && drRecord.iPriority > 0) {
    jBody["priority"] = drRecord.iPriority;
  }

  auto res = _upClient->Put(sPath, jBody.dump(), "application/json");
  if (!res) {
    return {false, "", "Failed to connect to DigitalOcean"};
  }
  if (res->status != 200) {
    std::string sError = "DigitalOcean update failed (status " +
                         std::to_string(res->status) + ")";
    try {
      auto jResp = json::parse(res->body);
      sError = jResp.value("message", sError);
    } catch (...) {}
    return {false, "", sError};
  }

  auto jResp = json::parse(res->body);
  std::string sNewId = std::to_string(
      jResp["domain_record"].at("id").get<int64_t>());
  spLog->info("DigitalOcean: updated record {} in zone {}", sNewId, sZoneName);
  return {true, sNewId, ""};
}

bool DigitalOceanProvider::deleteRecord(const std::string& sZoneName,
                                        const std::string& sProviderRecordId) {
  auto spLog = common::Logger::get();
  std::string sPath = "/v2/domains/" + sZoneName + "/records/" + sProviderRecordId;

  auto res = _upClient->Delete(sPath);
  if (!res) return false;
  if (res->status != 204) return false;

  spLog->info("DigitalOcean: deleted record {} from zone {}", sProviderRecordId, sZoneName);
  return true;
}

}  // namespace dns::providers
