#pragma once

#include <array>
#include <string_view>

namespace dns::common {

/// Metadata for a single DB-configurable setting.
struct SettingDef {
  std::string_view sKey;
  std::string_view sDefault;
  std::string_view sDescription;
  std::string_view sEnvVar;      // env var to seed from (empty if none)
  bool bRestartRequired;          // true if change needs restart
};

/// All DB-configurable settings. Source of truth for keys, defaults, and descriptions.
inline constexpr std::array<SettingDef, 15> kSettings = {{
  {"app.base_url", "", "Application base URL for generating callback URLs (e.g. https://dns.example.com)", "DNS_BASE_URL", false},
  {"http.threads", "4", "Number of HTTP server threads", "DNS_HTTP_THREADS", true},
  {"session.absolute_ttl_seconds", "86400", "Session absolute TTL in seconds",
   "DNS_SESSION_ABSOLUTE_TTL_SECONDS", false},
  {"session.cleanup_interval_seconds", "3600", "Session cleanup interval in seconds",
   "DNS_SESSION_CLEANUP_INTERVAL_SECONDS", false},
  {"apikey.cleanup_grace_seconds", "300", "API key cleanup grace period in seconds",
   "DNS_API_KEY_CLEANUP_GRACE_SECONDS", false},
  {"apikey.cleanup_interval_seconds", "3600", "API key cleanup interval in seconds",
   "DNS_API_KEY_CLEANUP_INTERVAL_SECONDS", false},
  {"deployment.retention_count", "10", "Number of deployment snapshots to retain per zone",
   "DNS_DEPLOYMENT_RETENTION_COUNT", false},
  {"ui.dir", "", "Path to built UI assets (empty = disabled)", "DNS_UI_DIR", true},
  {"migrations.dir", "/opt/meridian-dns/db", "Path to migration version directories",
   "DNS_MIGRATIONS_DIR", true},
  {"sync.check_interval_seconds", "3600", "Zone sync check interval in seconds (0 = disabled)",
   "DNS_SYNC_CHECK_INTERVAL", false},
  {"audit.db_url", "", "Separate audit database URL (empty = use main DB)",
   "DNS_AUDIT_DB_URL", true},
  {"audit.stdout", "false", "Also write audit entries to stdout", "DNS_AUDIT_STDOUT", false},
  {"audit.retention_days", "365", "Audit log retention in days",
   "DNS_AUDIT_RETENTION_DAYS", false},
  {"audit.purge_interval_seconds", "86400", "Audit purge interval in seconds",
   "DNS_AUDIT_PURGE_INTERVAL_SECONDS", false},
  {"gitops.base_path", "/var/meridian-dns/repos",
   "Base directory for git repository local clones", "DNS_GITOPS_BASE_PATH", true},
}};

}  // namespace dns::common
