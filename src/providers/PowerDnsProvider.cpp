#include "providers/PowerDnsProvider.hpp"

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

PowerDnsProvider::PowerDnsProvider(std::string sApiEndpoint, std::string sToken,
                                   nlohmann::json jConfig)
    : _sApiEndpoint(std::move(sApiEndpoint)),
      _sToken(std::move(sToken)),
      _sServerId(jConfig.value("server_id", "localhost")),
      _jConfig(std::move(jConfig)),
      _upClient(nullptr) {
  while (!_sApiEndpoint.empty() && _sApiEndpoint.back() == '/')
    _sApiEndpoint.pop_back();
  _upClient = std::make_unique<httplib::Client>(_sApiEndpoint);
  _upClient->set_default_headers({{"X-API-Key", _sToken}});
  _upClient->set_connection_timeout(5);
  _upClient->set_read_timeout(10);
}

PowerDnsProvider::~PowerDnsProvider() = default;

std::string PowerDnsProvider::name() const { return "powerdns"; }

std::string PowerDnsProvider::canonicalZone(const std::string& sZoneName) {
  if (sZoneName.empty() || sZoneName.back() == '.') return sZoneName;
  return sZoneName + ".";
}

std::string PowerDnsProvider::makeRecordId(const std::string& sName, const std::string& sType,
                                           const std::string& sValue) {
  return sName + "/" + sType + "/" + sValue;
}

bool PowerDnsProvider::parseRecordId(const std::string& sId, std::string& sName,
                                     std::string& sType, std::string& sValue) {
  auto iFirst = sId.find('/');
  if (iFirst == std::string::npos) return false;
  auto iSecond = sId.find('/', iFirst + 1);
  if (iSecond == std::string::npos) return false;

  sName = sId.substr(0, iFirst);
  sType = sId.substr(iFirst + 1, iSecond - iFirst - 1);
  sValue = sId.substr(iSecond + 1);
  return true;
}

common::HealthStatus PowerDnsProvider::testConnectivity() {
  auto spLog = common::Logger::get();
  try {
    auto res = _upClient->Get("/api/v1/servers");
    if (!res) {
      spLog->warn("PowerDNS {}: connection failed", _sApiEndpoint);
      return common::HealthStatus::Unreachable;
    }
    if (res->status == 200) {
      return common::HealthStatus::Ok;
    }
    spLog->warn("PowerDNS {}: unexpected status {}", _sApiEndpoint, res->status);
    return common::HealthStatus::Degraded;
  } catch (const std::exception& ex) {
    spLog->error("PowerDNS {}: connectivity test failed: {}", _sApiEndpoint, ex.what());
    return common::HealthStatus::Unreachable;
  }
}

std::vector<common::DnsRecord> PowerDnsProvider::parseZoneResponse(const std::string& sJson) {
  std::vector<common::DnsRecord> vRecords;
  auto jZone = json::parse(sJson);
  auto& jRrsets = jZone.at("rrsets");

  for (auto& jRrset : jRrsets) {
    std::string sName = jRrset.at("name").get<std::string>();
    std::string sType = jRrset.at("type").get<std::string>();
    uint32_t uTtl = jRrset.at("ttl").get<uint32_t>();

    for (auto& jRecord : jRrset.at("records")) {
      if (jRecord.value("disabled", false)) continue;

      std::string sContent = jRecord.at("content").get<std::string>();

      // TXT records: PowerDNS returns values with surrounding quotes — strip them
      // so they match the unquoted values stored in our database
      if (sType == "TXT" && sContent.size() >= 2 && sContent.front() == '"' &&
          sContent.back() == '"') {
        sContent = sContent.substr(1, sContent.size() - 2);
      }

      int iPriority = 0;

      // MX and SRV records: priority is the first token in content
      if (sType == "MX" || sType == "SRV") {
        auto iSpace = sContent.find(' ');
        if (iSpace != std::string::npos) {
          iPriority = std::stoi(sContent.substr(0, iSpace));
          sContent = sContent.substr(iSpace + 1);
        }
      }

      common::DnsRecord dr;
      dr.sProviderRecordId = makeRecordId(sName, sType, jRecord.at("content").get<std::string>());
      dr.sName = sName;
      dr.sType = sType;
      dr.uTtl = uTtl;
      dr.sValue = sContent;
      dr.iPriority = iPriority;
      vRecords.push_back(std::move(dr));
    }
  }

  return vRecords;
}

std::vector<common::DnsRecord> PowerDnsProvider::listRecords(const std::string& sZoneName) {
  auto spLog = common::Logger::get();
  std::string sCanonical = canonicalZone(sZoneName);
  std::string sPath = "/api/v1/servers/localhost/zones/" + sCanonical;

  auto res = _upClient->Get(sPath);
  if (!res) {
    throw common::ProviderError(
        "POWERDNS_UNREACHABLE",
        "Failed to connect to PowerDNS at " + _sApiEndpoint);
  }
  if (res->status != 200) {
    throw common::ProviderError(
        "POWERDNS_LIST_FAILED",
        "PowerDNS returned status " + std::to_string(res->status) +
            " for zone " + sCanonical);
  }

  spLog->debug("PowerDNS: listed records for zone {}", sCanonical);
  return parseZoneResponse(res->body);
}

common::PushResult PowerDnsProvider::createRecord(const std::string& sZoneName,
                                                  const common::DnsRecord& drRecord) {
  auto spLog = common::Logger::get();
  std::string sCanonical = canonicalZone(sZoneName);
  std::string sPath = "/api/v1/servers/localhost/zones/" + sCanonical;

  // First, fetch existing records for this name+type to build the full rrset
  std::vector<common::DnsRecord> vExisting;
  try {
    auto vAll = listRecords(sZoneName);
    for (auto& dr : vAll) {
      if (dr.sName == drRecord.sName && dr.sType == drRecord.sType) {
        vExisting.push_back(std::move(dr));
      }
    }
  } catch (const common::ProviderError&) {
    // Zone may not have any records yet — proceed with just the new record
  }

  // Build content string (MX/SRV prefix priority)
  std::string sContent = drRecord.sValue;
  if ((drRecord.sType == "MX" || drRecord.sType == "SRV") && drRecord.iPriority > 0) {
    sContent = std::to_string(drRecord.iPriority) + " " + drRecord.sValue;
  }

  // Build records array: existing + new
  json jRecords = json::array();
  for (const auto& dr : vExisting) {
    std::string sExistingContent = dr.sValue;
    if ((dr.sType == "MX" || dr.sType == "SRV") && dr.iPriority > 0) {
      sExistingContent = std::to_string(dr.iPriority) + " " + dr.sValue;
    }
    jRecords.push_back({{"content", sExistingContent}, {"disabled", false}});
  }
  jRecords.push_back({{"content", sContent}, {"disabled", false}});

  json jBody = {
      {"rrsets",
       {{{"name", drRecord.sName},
         {"type", drRecord.sType},
         {"ttl", drRecord.uTtl},
         {"changetype", "REPLACE"},
         {"records", jRecords}}}}};

  auto res = _upClient->Patch(sPath, jBody.dump(), "application/json");
  if (!res) {
    return {false, "", "Failed to connect to PowerDNS"};
  }
  if (res->status != 204 && res->status != 200) {
    return {false, "", "PowerDNS returned status " + std::to_string(res->status)};
  }

  std::string sNewId = makeRecordId(drRecord.sName, drRecord.sType, sContent);
  spLog->info("PowerDNS: created record {} in zone {}", sNewId, sCanonical);
  return {true, sNewId, ""};
}

common::PushResult PowerDnsProvider::updateRecord(const std::string& sZoneName,
                                                  const common::DnsRecord& drRecord) {
  auto spLog = common::Logger::get();
  std::string sCanonical = canonicalZone(sZoneName);
  std::string sPath = "/api/v1/servers/localhost/zones/" + sCanonical;

  std::string sOldName, sOldType, sOldValue;
  if (!parseRecordId(drRecord.sProviderRecordId, sOldName, sOldType, sOldValue)) {
    return {false, "", "Invalid provider_record_id format"};
  }

  // Fetch existing rrset for this name+type
  auto vAll = listRecords(sZoneName);
  json jRecords = json::array();
  for (const auto& dr : vAll) {
    if (dr.sName != sOldName || dr.sType != sOldType) continue;

    std::string sContent;
    // Check if this is the record being updated
    std::string sCheckName, sCheckType, sCheckValue;
    parseRecordId(dr.sProviderRecordId, sCheckName, sCheckType, sCheckValue);
    if (sCheckValue == sOldValue) {
      // This is the record to update — use new value
      sContent = drRecord.sValue;
      if ((drRecord.sType == "MX" || drRecord.sType == "SRV") && drRecord.iPriority > 0) {
        sContent = std::to_string(drRecord.iPriority) + " " + drRecord.sValue;
      }
    } else {
      // Keep existing record as-is
      sContent = dr.sValue;
      if ((dr.sType == "MX" || dr.sType == "SRV") && dr.iPriority > 0) {
        sContent = std::to_string(dr.iPriority) + " " + dr.sValue;
      }
    }
    jRecords.push_back({{"content", sContent}, {"disabled", false}});
  }

  json jBody = {
      {"rrsets",
       {{{"name", sOldName},
         {"type", sOldType},
         {"ttl", drRecord.uTtl},
         {"changetype", "REPLACE"},
         {"records", jRecords}}}}};

  auto res = _upClient->Patch(sPath, jBody.dump(), "application/json");
  if (!res) {
    return {false, "", "Failed to connect to PowerDNS"};
  }
  if (res->status != 204 && res->status != 200) {
    return {false, "", "PowerDNS returned status " + std::to_string(res->status)};
  }

  std::string sNewContent = drRecord.sValue;
  if ((drRecord.sType == "MX" || drRecord.sType == "SRV") && drRecord.iPriority > 0) {
    sNewContent = std::to_string(drRecord.iPriority) + " " + drRecord.sValue;
  }
  std::string sNewId = makeRecordId(sOldName, sOldType, sNewContent);
  spLog->info("PowerDNS: updated record {} -> {} in zone {}", drRecord.sProviderRecordId, sNewId,
              sCanonical);
  return {true, sNewId, ""};
}

bool PowerDnsProvider::deleteRecord(const std::string& sZoneName,
                                    const std::string& sProviderRecordId) {
  auto spLog = common::Logger::get();
  std::string sCanonical = canonicalZone(sZoneName);
  std::string sPath = "/api/v1/servers/localhost/zones/" + sCanonical;

  std::string sTargetName, sTargetType, sTargetValue;
  if (!parseRecordId(sProviderRecordId, sTargetName, sTargetType, sTargetValue)) {
    return false;
  }

  // Fetch existing rrset, remove the target record
  auto vAll = listRecords(sZoneName);
  json jRecords = json::array();
  bool bFound = false;
  for (const auto& dr : vAll) {
    if (dr.sName != sTargetName || dr.sType != sTargetType) continue;
    std::string sCheckName, sCheckType, sCheckValue;
    parseRecordId(dr.sProviderRecordId, sCheckName, sCheckType, sCheckValue);
    if (sCheckValue == sTargetValue) {
      bFound = true;
      continue;  // skip — this is the one to delete
    }
    std::string sContent = dr.sValue;
    if ((dr.sType == "MX" || dr.sType == "SRV") && dr.iPriority > 0) {
      sContent = std::to_string(dr.iPriority) + " " + dr.sValue;
    }
    jRecords.push_back({{"content", sContent}, {"disabled", false}});
  }

  if (!bFound) return false;

  // If no records remain, delete the entire rrset; otherwise replace
  std::string sChangetype = jRecords.empty() ? "DELETE" : "REPLACE";
  json jRrset = {{"name", sTargetName}, {"type", sTargetType}, {"changetype", sChangetype}};
  if (!jRecords.empty()) {
    jRrset["ttl"] = vAll.front().uTtl;  // preserve TTL from existing
    jRrset["records"] = jRecords;
  }

  json jBody = {{"rrsets", {jRrset}}};
  auto res = _upClient->Patch(sPath, jBody.dump(), "application/json");
  if (!res) return false;
  if (res->status != 204 && res->status != 200) return false;

  spLog->info("PowerDNS: deleted record {} from zone {}", sProviderRecordId, sCanonical);
  return true;
}

}  // namespace dns::providers
