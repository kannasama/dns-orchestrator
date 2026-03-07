#include "providers/CloudflareProvider.hpp"

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

CloudflareProvider::CloudflareProvider(std::string sApiEndpoint, std::string sToken,
                                       nlohmann::json jConfig)
    : _sApiEndpoint(std::move(sApiEndpoint)),
      _sToken(std::move(sToken)),
      _sAccountId(jConfig.value("account_id", "")),
      _jConfig(std::move(jConfig)),
      _upClient(std::make_unique<httplib::Client>(_sApiEndpoint)) {
  _upClient->set_default_headers({
      {"Authorization", "Bearer " + _sToken},
      {"Content-Type", "application/json"},
  });
  _upClient->set_connection_timeout(10);
  _upClient->set_read_timeout(30);
}

CloudflareProvider::~CloudflareProvider() = default;

std::string CloudflareProvider::name() const { return "cloudflare"; }

// ---------------------------------------------------------------------------
// Zone ID resolution
// ---------------------------------------------------------------------------

std::string CloudflareProvider::parseZoneIdResponse(const std::string& sJson,
                                                     const std::string& sZoneName) {
  auto jResp = json::parse(sJson);

  if (!jResp.value("success", false)) {
    std::string sError = "Cloudflare API error";
    if (jResp.contains("errors") && !jResp["errors"].empty()) {
      sError = jResp["errors"][0].value("message", sError);
    }
    throw common::ProviderError("CF_API_ERROR", sError);
  }

  auto& jResult = jResp.at("result");
  if (jResult.empty()) {
    throw common::ProviderError("CF_ZONE_NOT_FOUND",
                                "Zone '" + sZoneName + "' not found in Cloudflare account");
  }

  return jResult[0].at("id").get<std::string>();
}

std::string CloudflareProvider::resolveZoneId(const std::string& sZoneName) {
  auto it = _mZoneIdCache.find(sZoneName);
  if (it != _mZoneIdCache.end()) return it->second;

  std::string sPath = "/client/v4/zones?name=" + sZoneName + "&status=active";
  auto res = _upClient->Get(sPath);
  if (!res) {
    throw common::ProviderError("CF_UNREACHABLE",
                                "Failed to connect to Cloudflare at " + _sApiEndpoint);
  }
  if (res->status != 200) {
    throw common::ProviderError("CF_ZONE_LOOKUP_FAILED",
                                "Cloudflare returned status " + std::to_string(res->status));
  }

  auto sZoneId = parseZoneIdResponse(res->body, sZoneName);
  _mZoneIdCache[sZoneName] = sZoneId;
  return sZoneId;
}

// ---------------------------------------------------------------------------
// testConnectivity
// ---------------------------------------------------------------------------

common::HealthStatus CloudflareProvider::testConnectivity() {
  auto spLog = common::Logger::get();
  try {
    auto res = _upClient->Get("/client/v4/user/tokens/verify");
    if (!res) {
      spLog->warn("Cloudflare {}: connection failed", _sApiEndpoint);
      return common::HealthStatus::Unreachable;
    }
    if (res->status == 200) {
      auto jResp = json::parse(res->body);
      if (jResp.value("success", false)) {
        return common::HealthStatus::Ok;
      }
    }
    spLog->warn("Cloudflare {}: unexpected status {}", _sApiEndpoint, res->status);
    return common::HealthStatus::Degraded;
  } catch (const std::exception& ex) {
    spLog->error("Cloudflare {}: connectivity test failed: {}", _sApiEndpoint, ex.what());
    return common::HealthStatus::Unreachable;
  }
}

// ---------------------------------------------------------------------------
// listRecords + parseRecordsResponse
// ---------------------------------------------------------------------------

std::vector<common::DnsRecord> CloudflareProvider::parseRecordsResponse(
    const std::string& sJson) {
  std::vector<common::DnsRecord> vRecords;
  auto jResp = json::parse(sJson);

  if (!jResp.value("success", false)) {
    std::string sError = "Cloudflare API error";
    if (jResp.contains("errors") && !jResp["errors"].empty()) {
      sError = jResp["errors"][0].value("message", sError);
    }
    throw common::ProviderError("CF_API_ERROR", sError);
  }

  for (const auto& jRec : jResp.at("result")) {
    common::DnsRecord dr;
    dr.sProviderRecordId = jRec.at("id").get<std::string>();
    dr.sName = jRec.at("name").get<std::string>();
    dr.sType = jRec.at("type").get<std::string>();
    dr.uTtl = jRec.at("ttl").get<uint32_t>();
    dr.sValue = jRec.at("content").get<std::string>();
    dr.iPriority = jRec.value("priority", 0);

    // Capture provider-specific metadata
    bool bProxied = jRec.value("proxied", false);
    dr.jProviderMeta = {{"proxied", bProxied}};

    vRecords.push_back(std::move(dr));
  }

  return vRecords;
}

std::vector<common::DnsRecord> CloudflareProvider::listRecords(
    const std::string& sZoneName) {
  auto spLog = common::Logger::get();
  auto sZoneId = resolveZoneId(sZoneName);

  std::vector<common::DnsRecord> vAll;
  int iPage = 1;
  int iTotalPages = 1;

  while (iPage <= iTotalPages) {
    std::string sPath = "/client/v4/zones/" + sZoneId +
                        "/dns_records?per_page=100&page=" + std::to_string(iPage);
    auto res = _upClient->Get(sPath);
    if (!res) {
      throw common::ProviderError("CF_UNREACHABLE",
                                  "Failed to connect to Cloudflare at " + _sApiEndpoint);
    }
    if (res->status != 200) {
      throw common::ProviderError("CF_LIST_FAILED",
                                  "Cloudflare returned status " + std::to_string(res->status));
    }

    auto jResp = json::parse(res->body);
    auto vPage = parseRecordsResponse(res->body);
    vAll.insert(vAll.end(), vPage.begin(), vPage.end());

    if (jResp.contains("result_info")) {
      iTotalPages = jResp["result_info"].value("total_pages", 1);
    }
    ++iPage;
  }

  spLog->debug("Cloudflare: listed {} records for zone {} ({})", vAll.size(), sZoneName,
               sZoneId);
  return vAll;
}

// ---------------------------------------------------------------------------
// CRUD: buildRecordBody, createRecord, updateRecord, deleteRecord
// ---------------------------------------------------------------------------

nlohmann::json CloudflareProvider::buildRecordBody(const common::DnsRecord& drRecord) {
  json jBody = {
      {"type", drRecord.sType},
      {"name", drRecord.sName},
      {"content", drRecord.sValue},
      {"ttl", drRecord.uTtl},
  };

  // MX/SRV have priority as a separate field in Cloudflare API
  if ((drRecord.sType == "MX" || drRecord.sType == "SRV") && drRecord.iPriority > 0) {
    jBody["priority"] = drRecord.iPriority;
  }

  // Proxy support — only for A/AAAA/CNAME
  bool bProxied = false;
  if (!drRecord.jProviderMeta.is_null()) {
    bProxied = drRecord.jProviderMeta.value("proxied", false);
  }
  if (drRecord.sType == "A" || drRecord.sType == "AAAA" || drRecord.sType == "CNAME") {
    jBody["proxied"] = bProxied;
  }

  return jBody;
}

common::PushResult CloudflareProvider::createRecord(const std::string& sZoneName,
                                                    const common::DnsRecord& drRecord) {
  auto spLog = common::Logger::get();
  auto sZoneId = resolveZoneId(sZoneName);
  std::string sPath = "/client/v4/zones/" + sZoneId + "/dns_records";

  auto jBody = buildRecordBody(drRecord);
  auto res = _upClient->Post(sPath, jBody.dump(), "application/json");
  if (!res) {
    return {false, "", "Failed to connect to Cloudflare"};
  }

  auto jResp = json::parse(res->body);
  if (res->status != 200 || !jResp.value("success", false)) {
    std::string sError = "Cloudflare create failed";
    if (jResp.contains("errors") && !jResp["errors"].empty()) {
      sError = jResp["errors"][0].value("message", sError);
    }
    return {false, "", sError};
  }

  std::string sNewId = jResp["result"].at("id").get<std::string>();
  spLog->info("Cloudflare: created record {} in zone {}", sNewId, sZoneName);
  return {true, sNewId, ""};
}

common::PushResult CloudflareProvider::updateRecord(const std::string& sZoneName,
                                                    const common::DnsRecord& drRecord) {
  auto spLog = common::Logger::get();
  auto sZoneId = resolveZoneId(sZoneName);
  std::string sPath = "/client/v4/zones/" + sZoneId + "/dns_records/" +
                      drRecord.sProviderRecordId;

  auto jBody = buildRecordBody(drRecord);
  auto res = _upClient->Patch(sPath, jBody.dump(), "application/json");
  if (!res) {
    return {false, "", "Failed to connect to Cloudflare"};
  }

  auto jResp = json::parse(res->body);
  if (res->status != 200 || !jResp.value("success", false)) {
    std::string sError = "Cloudflare update failed";
    if (jResp.contains("errors") && !jResp["errors"].empty()) {
      sError = jResp["errors"][0].value("message", sError);
    }
    return {false, "", sError};
  }

  std::string sNewId = jResp["result"].at("id").get<std::string>();
  spLog->info("Cloudflare: updated record {} in zone {}", sNewId, sZoneName);
  return {true, sNewId, ""};
}

bool CloudflareProvider::deleteRecord(const std::string& sZoneName,
                                      const std::string& sProviderRecordId) {
  auto spLog = common::Logger::get();
  auto sZoneId = resolveZoneId(sZoneName);
  std::string sPath = "/client/v4/zones/" + sZoneId + "/dns_records/" + sProviderRecordId;

  auto res = _upClient->Delete(sPath);
  if (!res) return false;

  if (res->status != 200) return false;

  auto jResp = json::parse(res->body);
  if (!jResp.value("success", false)) return false;

  spLog->info("Cloudflare: deleted record {} from zone {}", sProviderRecordId, sZoneName);
  return true;
}

}  // namespace dns::providers
