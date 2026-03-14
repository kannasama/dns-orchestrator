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

void RequestValidator::validateGitRepoName(const std::string& sName) {
  validateRequired(sName, "name");
  validateStringLength(sName, "name", 100);
}

void RequestValidator::validateGitRemoteUrl(const std::string& sUrl) {
  validateRequired(sUrl, "remote_url");
  validateStringLength(sUrl, "remote_url", 500);
  if (sUrl.rfind("git@", 0) != 0 && sUrl.rfind("ssh://", 0) != 0 &&
      sUrl.rfind("https://", 0) != 0 && sUrl.rfind("http://", 0) != 0 &&
      sUrl.rfind("file://", 0) != 0) {
    throw dns::common::ValidationError(
        "INVALID_REMOTE_URL",
        "remote_url must start with git@, ssh://, https://, http://, or file://");
  }
}

void RequestValidator::validateGitAuthType(const std::string& sAuthType) {
  if (sAuthType != "ssh" && sAuthType != "https" && sAuthType != "none") {
    throw dns::common::ValidationError(
        "INVALID_AUTH_TYPE", "auth_type must be 'ssh', 'https', or 'none'");
  }
}

void RequestValidator::validateGitBranch(const std::string& sBranch) {
  if (sBranch.empty()) return;
  validateStringLength(sBranch, "branch", 100);
  if (sBranch[0] == '-' || sBranch.find("..") != std::string::npos) {
    throw dns::common::ValidationError(
        "INVALID_BRANCH", "Invalid git branch name");
  }
}

}  // namespace dns::api
