#include "api/RequestValidator.hpp"
#include <regex>
#include <unordered_set>

namespace dns::api {

void RequestValidator::validateStringLength(const std::string& sValue,
                                            const std::string& sFieldName,
                                            size_t nMaxLength) {
  if (sValue.empty())
    throw common::ValidationError("FIELD_REQUIRED", sFieldName + " is required");
  if (sValue.size() > nMaxLength)
    throw common::ValidationError("FIELD_TOO_LONG",
        sFieldName + " exceeds maximum length of " + std::to_string(nMaxLength));
}

void RequestValidator::validateRequired(const std::string& sValue,
                                        const std::string& sFieldName) {
  if (sValue.empty())
    throw common::ValidationError("FIELD_REQUIRED", sFieldName + " is required");
}

void RequestValidator::validateZoneName(const std::string& s) { validateStringLength(s, "zone_name", 253); }
void RequestValidator::validateRecordName(const std::string& s) { validateStringLength(s, "record_name", 253); }
void RequestValidator::validateValueTemplate(const std::string& s) { validateStringLength(s, "value_template", 4096); }
void RequestValidator::validateVariableValue(const std::string& s) { validateStringLength(s, "variable_value", 4096); }
void RequestValidator::validateProviderName(const std::string& s) { validateStringLength(s, "provider_name", 128); }
void RequestValidator::validateUsername(const std::string& s) { validateStringLength(s, "username", 128); }
void RequestValidator::validatePassword(const std::string& s) { validateStringLength(s, "password", 1024); }
void RequestValidator::validateGroupName(const std::string& s) { validateStringLength(s, "group_name", 128); }

void RequestValidator::validateRecordType(const std::string& sType) {
  static const std::unordered_set<std::string> st = {"A","AAAA","CNAME","MX","TXT","SRV","NS","PTR"};
  if (st.find(sType) == st.end())
    throw common::ValidationError("INVALID_RECORD_TYPE",
        "Record type must be one of: A, AAAA, CNAME, MX, TXT, SRV, NS, PTR");
}

void RequestValidator::validateTtl(int iTtl) {
  if (iTtl < 1 || iTtl > 604800)
    throw common::ValidationError("INVALID_TTL", "TTL must be between 1 and 604800 seconds");
}

void RequestValidator::validateVariableName(const std::string& sName) {
  validateStringLength(sName, "variable_name", 64);
  static const std::regex rx("^[A-Za-z0-9_]+$");
  if (!std::regex_match(sName, rx))
    throw common::ValidationError("INVALID_VARIABLE_NAME",
        "Variable name must contain only alphanumeric characters and underscores");
}

void RequestValidator::validateProviderType(const std::string& sType) {
  static const std::unordered_set<std::string> st = {"powerdns","cloudflare","digitalocean"};
  if (st.find(sType) == st.end())
    throw common::ValidationError("INVALID_PROVIDER_TYPE",
        "Provider type must be one of: powerdns, cloudflare, digitalocean");
}

void RequestValidator::validateApiKeyDescription(const std::string& s) {
  if (!s.empty() && s.size() > 512)
    throw common::ValidationError("FIELD_TOO_LONG",
        "api_key_description exceeds maximum length of 512");
}

}  // namespace dns::api
