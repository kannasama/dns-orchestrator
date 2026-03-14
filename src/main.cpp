#include <chrono>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string_view>

#include "api/ApiServer.hpp"
#include "api/AuthMiddleware.hpp"
#include "api/StaticFileHandler.hpp"
#include "api/routes/ApiKeyRoutes.hpp"
#include "api/routes/AuthRoutes.hpp"
#include "api/routes/GroupRoutes.hpp"
#include "api/routes/HealthRoutes.hpp"
#include "api/routes/ThemeRoutes.hpp"
#include "api/routes/ProviderRoutes.hpp"
#include "api/routes/RecordRoutes.hpp"
#include "api/routes/RoleRoutes.hpp"
#include "api/routes/SettingsRoutes.hpp"
#include "api/routes/SetupRoutes.hpp"
#include "api/routes/UserRoutes.hpp"
#include "api/routes/VariableRoutes.hpp"
#include "api/routes/ViewRoutes.hpp"
#include "api/routes/ZoneRoutes.hpp"
#include "api/routes/GitRepoRoutes.hpp"
#include "api/routes/IdpRoutes.hpp"
#include "api/routes/OidcRoutes.hpp"
#include "api/routes/SamlRoutes.hpp"
#include "common/Config.hpp"
#include "common/Logger.hpp"
#include "api/routes/AuditRoutes.hpp"
#include "api/routes/DeploymentRoutes.hpp"
#include "core/DeploymentEngine.hpp"
#include "core/DiffEngine.hpp"
#include "core/MaintenanceScheduler.hpp"
#include "core/RollbackEngine.hpp"
#include "core/ThreadPool.hpp"
#include "core/VariableEngine.hpp"
#include "gitops/GitRepoManager.hpp"
#include "gitops/GitOpsMigration.hpp"
#include "dal/GitRepoRepository.hpp"
#include "dal/ApiKeyRepository.hpp"
#include "dal/AuditRepository.hpp"
#include "dal/ConnectionPool.hpp"
#include "dal/DeploymentRepository.hpp"
#include "dal/GroupRepository.hpp"
#include "dal/IdpRepository.hpp"
#include "dal/MigrationRunner.hpp"
#include "dal/RoleRepository.hpp"
#include "dal/ProviderRepository.hpp"
#include "dal/RecordRepository.hpp"
#include "dal/SessionRepository.hpp"
#include "dal/SettingsRepository.hpp"
#include "dal/UserRepository.hpp"
#include "dal/VariableRepository.hpp"
#include "dal/ViewRepository.hpp"
#include "dal/ZoneRepository.hpp"
#include "security/AuthService.hpp"
#include "security/CryptoService.hpp"
#include "security/FederatedAuthService.hpp"
#include "security/HmacJwtSigner.hpp"
#include "security/IJwtSigner.hpp"
#include "security/OidcService.hpp"
#include "security/SamlReplayCache.hpp"
#include "security/SamlService.hpp"

#include <termios.h>
#include <unistd.h>

#include <openssl/crypto.h>

// Startup sequence from ARCHITECTURE.md §11.4
//
// Phase 6 implements steps 1-5, 7a, 8, 9, 10, 11. Steps 6, 7, 12 remain deferred.

namespace {
// Global pointer for signal handler access
dns::api::ApiServer* g_pApiServer = nullptr;
dns::core::MaintenanceScheduler* g_pScheduler = nullptr;

void signalHandler(int /*iSignal*/) {
  if (g_pApiServer) g_pApiServer->stop();
}
// NOLINTNEXTLINE(cert-err58-cpp) — version string must be available before Config::load()
constexpr std::string_view kVersion = "0.1.0";

void printUsage(const char* pProgName) {
  std::cout << "Usage: " << pProgName << " [OPTIONS]\n"
            << "\n"
            << "Meridian DNS — Multi-Provider DNS Management\n"
            << "\n"
            << "Options:\n"
            << "  --help                    Show this help message and exit\n"
            << "  --version                 Show version information and exit\n"
            << "  --migrate                 Run database migrations and exit\n"
            << "  --reset-password <user>   Reset a user's password\n"
            << "\n"
            << "Environment variables (required):\n"
            << "  DNS_DB_URL          PostgreSQL connection string\n"
            << "  DNS_MASTER_KEY      Encryption master key (or DNS_MASTER_KEY_FILE)\n"
            << "  DNS_JWT_SECRET      JWT signing secret  (or DNS_JWT_SECRET_FILE)\n"
            << "\n"
            << "See README.md or .env.example for optional configuration.\n";
}

}  // namespace

int main(int argc, char* argv[]) {
  // ── CLI argument handling (before any config/resource init) ──────────
  for (int i = 1; i < argc; ++i) {
    const std::string_view arg{argv[i]};
    if (arg == "--help" || arg == "-h") {
      printUsage(argv[0]);
      // quick_exit avoids libpqxx static-destruction double-free (strconv.hxx:80);
      // flush explicitly since quick_exit skips stdio cleanup
      std::cout.flush();
      std::quick_exit(EXIT_SUCCESS);
    }
    if (arg == "--version" || arg == "-v") {
      std::cout << "meridian-dns " << kVersion << "\n";
      std::cout.flush();
      std::quick_exit(EXIT_SUCCESS);
    }
    if (arg == "--migrate") {
      // Migration-only mode: need DB URL from config
      try {
        auto cfgApp = dns::common::Config::load();
        dns::common::Logger::init(cfgApp.sLogLevel);
        auto spLog = dns::common::Logger::get();

        dns::dal::MigrationRunner mrRunner(cfgApp.sDbUrl, cfgApp.sMigrationsDir);
        int iVersion = mrRunner.migrate();
        spLog->info("Migrations complete. Schema version: {}", iVersion);
        std::cout << "Migrations complete. Schema version: " << iVersion << "\n";
        std::cout.flush();
      } catch (const std::exception& ex) {
        std::cerr << "[fatal] migration failed: " << ex.what() << std::endl;
        std::cerr.flush();
        std::quick_exit(EXIT_FAILURE);
      }
      std::quick_exit(EXIT_SUCCESS);
    }
    if (arg == "--reset-password") {
      if (i + 1 >= argc) {
        std::cerr << "Usage: --reset-password <username>\n";
        std::cerr.flush();
        std::quick_exit(EXIT_FAILURE);
      }
      std::string sUsername = argv[++i];
      try {
        auto cfgApp = dns::common::Config::load();
        dns::common::Logger::init(cfgApp.sLogLevel);

        dns::dal::ConnectionPool cpPool(cfgApp.sDbUrl, 1);
        dns::dal::UserRepository urRepo(cpPool);

        auto oUser = urRepo.findByUsername(sUsername);
        if (!oUser) {
          std::cerr << "User '" << sUsername << "' not found\n";
          std::cerr.flush();
          std::quick_exit(EXIT_FAILURE);
        }

        // Read password from stdin (supports piping and interactive)
        std::string sNewPassword;
        if (isatty(STDIN_FILENO)) {
          std::cout << "New password for '" << sUsername << "': " << std::flush;
          struct termios tOld, tNew;
          tcgetattr(STDIN_FILENO, &tOld);
          tNew = tOld;
          tNew.c_lflag &= ~ECHO;
          tcsetattr(STDIN_FILENO, TCSANOW, &tNew);
          std::getline(std::cin, sNewPassword);
          tcsetattr(STDIN_FILENO, TCSANOW, &tOld);
          std::cout << "\n";
        } else {
          std::getline(std::cin, sNewPassword);
        }

        if (sNewPassword.empty() || sNewPassword.size() < 8) {
          std::cerr << "Password must be at least 8 characters\n";
          std::cerr.flush();
          std::quick_exit(EXIT_FAILURE);
        }

        std::string sHash = dns::security::CryptoService::hashPassword(sNewPassword);
        urRepo.updatePassword(oUser->iId, sHash);
        urRepo.setForcePasswordChange(oUser->iId, true);

        std::cout << "Password reset for '" << sUsername << "'. "
                  << "User will be prompted to change password on next login.\n";
        std::cout.flush();
      } catch (const std::exception& ex) {
        std::cerr << "[fatal] password reset failed: " << ex.what() << std::endl;
        std::cerr.flush();
        std::quick_exit(EXIT_FAILURE);
      }
      std::quick_exit(EXIT_SUCCESS);
    }
    std::cerr << "Unknown option: " << arg << "\n";
    printUsage(argv[0]);
    std::cout.flush();
    std::cerr.flush();
    std::quick_exit(EXIT_FAILURE);
  }

  try {
    // ── Step 1: Load and validate configuration ──────────────────────────
    auto cfgApp = dns::common::Config::load();

    // Initialize logger with configured level
    dns::common::Logger::init(cfgApp.sLogLevel);
    auto spLog = dns::common::Logger::get();
    spLog->info("Step 1: Configuration loaded successfully");

    // ── Step 0: Run database migrations ──────────────────────────────────
    {
      dns::dal::MigrationRunner mrRunner(cfgApp.sDbUrl, cfgApp.sMigrationsDir);
      int iVersion = mrRunner.migrate();
      spLog->info("Step 0: Database migrations complete (schema version: {})", iVersion);
    }

    // ── Step 0b: Seed and load DB settings ──────────────────────────────
    {
      dns::dal::ConnectionPool cpSeedPool(cfgApp.sDbUrl, 1);
      dns::dal::SettingsRepository srSeedRepo(cpSeedPool);
      dns::common::Config::seedToDb(srSeedRepo);
      cfgApp.loadFromDb(srSeedRepo);
      spLog->info("Step 0b: Settings seeded and loaded from database");
    }

    // ── Step 2: Initialize CryptoService ─────────────────────────────────
    auto csService = std::make_unique<dns::security::CryptoService>(cfgApp.sMasterKey);

    // Zero master key from Config after handoff (SEC-02)
    OPENSSL_cleanse(cfgApp.sMasterKey.data(), cfgApp.sMasterKey.size());
    cfgApp.sMasterKey.clear();

    spLog->info("Step 2: CryptoService initialized");

    // ── Step 3: Construct IJwtSigner ─────────────────────────────────────
    std::unique_ptr<dns::security::IJwtSigner> upSigner;
    if (cfgApp.sJwtAlgorithm == "HS256") {
      upSigner = std::make_unique<dns::security::HmacJwtSigner>(cfgApp.sJwtSecret);
    } else {
      throw std::runtime_error(
          "Unsupported JWT algorithm: " + cfgApp.sJwtAlgorithm +
          " (only HS256 is currently implemented)");
    }

    // Zero JWT secret from Config after handoff (SEC-02)
    OPENSSL_cleanse(cfgApp.sJwtSecret.data(), cfgApp.sJwtSecret.size());
    cfgApp.sJwtSecret.clear();

    spLog->info("Step 3: IJwtSigner constructed (algorithm={})", cfgApp.sJwtAlgorithm);

    // ── Step 4: Initialize ConnectionPool ────────────────────────────────
    auto cpPool = std::make_unique<dns::dal::ConnectionPool>(
        cfgApp.sDbUrl, cfgApp.iDbPoolSize);
    spLog->info("Step 4: ConnectionPool initialized (size={})", cfgApp.iDbPoolSize);

    // ── Step 5: Foundation ready ─────────────────────────────────────────
    spLog->info("Step 5: Foundation layer ready");

    // ── Step 6: GitRepoManager (initialized after engines in Step 9) ──────
    spLog->info("Step 6: GitRepoManager deferred until engines ready");

    // ── Step 7: Initialize ThreadPool ──────────────────────────────────────
    auto tpPool = std::make_unique<dns::core::ThreadPool>(cfgApp.iThreadPoolSize);
    spLog->info("Step 7: ThreadPool initialized (size={})",
                cfgApp.iThreadPoolSize == 0
                    ? static_cast<int>(std::thread::hardware_concurrency())
                    : cfgApp.iThreadPoolSize);

    // ── Step 7a: Initialize repositories + MaintenanceScheduler ──────────
    auto urRepo = std::make_unique<dns::dal::UserRepository>(*cpPool);
    auto srRepo = std::make_unique<dns::dal::SessionRepository>(*cpPool);
    auto akrRepo = std::make_unique<dns::dal::ApiKeyRepository>(*cpPool);

    // Phase 5 repositories
    auto prRepo = std::make_unique<dns::dal::ProviderRepository>(*cpPool, *csService);
    auto vrRepo = std::make_unique<dns::dal::ViewRepository>(*cpPool);
    auto zrRepo = std::make_unique<dns::dal::ZoneRepository>(*cpPool);
    auto rrRepo = std::make_unique<dns::dal::RecordRepository>(*cpPool);
    auto varRepo = std::make_unique<dns::dal::VariableRepository>(*cpPool);
    auto drRepo = std::make_unique<dns::dal::DeploymentRepository>(*cpPool);
    auto arRepo = std::make_unique<dns::dal::AuditRepository>(*cpPool);
    auto grRepo = std::make_unique<dns::dal::GroupRepository>(*cpPool);
    auto roleRepo = std::make_unique<dns::dal::RoleRepository>(*cpPool);
    auto settingsRepo = std::make_unique<dns::dal::SettingsRepository>(*cpPool);
    auto idpRepo = std::make_unique<dns::dal::IdpRepository>(*cpPool, *csService);
    auto gitRepoRepo = std::make_unique<dns::dal::GitRepoRepository>(*cpPool, *csService);

    auto msScheduler = std::make_unique<dns::core::MaintenanceScheduler>();

    msScheduler->schedule("session-flush",
                          std::chrono::seconds(cfgApp.iSessionCleanupIntervalSeconds),
                          [&srRepo]() {
                            int iDeleted = srRepo->pruneExpired();
                            if (iDeleted > 0) {
                              auto spLog = dns::common::Logger::get();
                              spLog->info("Session flush: deleted {} expired sessions", iDeleted);
                            }
                          });

    msScheduler->schedule("api-key-cleanup",
                          std::chrono::seconds(cfgApp.iApiKeyCleanupIntervalSeconds),
                          [&akrRepo]() {
                            int iDeleted = akrRepo->pruneScheduled();
                            if (iDeleted > 0) {
                              auto spLog = dns::common::Logger::get();
                              spLog->info("API key cleanup: deleted {} scheduled keys", iDeleted);
                            }
                          });

    msScheduler->schedule("audit-purge",
                          std::chrono::seconds(cfgApp.iAuditPurgeIntervalSeconds),
                          [&arRepo, iRetention = cfgApp.iAuditRetentionDays]() {
                            auto pr = arRepo->purgeOld(iRetention);
                            if (pr.iDeletedCount > 0) {
                              auto spLog = dns::common::Logger::get();
                              spLog->info("Audit purge: deleted {} old entries", pr.iDeletedCount);
                            }
                          });

    msScheduler->start();
    g_pScheduler = msScheduler.get();
    spLog->info("Step 7a: MaintenanceScheduler started (session flush every {}s, "
                "API key cleanup every {}s, audit purge every {}s)",
                cfgApp.iSessionCleanupIntervalSeconds,
                cfgApp.iApiKeyCleanupIntervalSeconds,
                cfgApp.iAuditPurgeIntervalSeconds);

    // ── Step 7b: Setup mode detection ────────────────────────────────────
    auto setupRoutes = std::make_unique<dns::api::routes::SetupRoutes>(
        *cpPool, *urRepo, *upSigner);
    setupRoutes->loadSetupState();

    std::string sSetupToken;
    if (!setupRoutes->isSetupCompleted()) {
      // Generate a 30-minute setup JWT
      auto iNow = std::chrono::duration_cast<std::chrono::seconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                       .count();
      nlohmann::json jSetupPayload = {
          {"purpose", "setup"},
          {"iat", iNow},
          {"exp", iNow + 1800},  // 30 minutes
      };
      sSetupToken = upSigner->sign(jSetupPayload);
      setupRoutes->setSetupToken(sSetupToken);
      spLog->info("Step 7b: Setup mode ACTIVE — complete setup via web UI within 30 minutes");
    } else {
      spLog->info("Step 7b: Setup already completed");
    }

    // ── Step 8: Initialize SamlReplayCache ────────────────────────────────
    auto srcCache = std::make_unique<dns::security::SamlReplayCache>();
    auto oidcService = std::make_unique<dns::security::OidcService>();
    auto samlService = std::make_unique<dns::security::SamlService>(*srcCache);
    spLog->info("Step 8: SamlReplayCache + OIDC/SAML services initialized");

    // ── Step 9: Core engines ─────────────────────────────────────────────
    auto veEngine = std::make_unique<dns::core::VariableEngine>(*varRepo);
    auto deEngine = std::make_unique<dns::core::DiffEngine>(
        *zrRepo, *vrRepo, *rrRepo, *prRepo, *veEngine);

    // ── Step 6a: Migrate legacy env vars to git_repos table ──────────────
    dns::gitops::GitOpsMigration::migrateIfNeeded(*gitRepoRepo, *zrRepo);

    // ── Step 6b: Initialize GitRepoManager ─────────────────────────────────
    std::string sGitBasePath = settingsRepo->getValue("gitops.base_path",
                                                      "/var/meridian-dns/repos");
    auto upGitRepoManager = std::make_unique<dns::gitops::GitRepoManager>(
        *gitRepoRepo, *zrRepo, *vrRepo, *rrRepo, *veEngine, sGitBasePath);
    upGitRepoManager->initialize();
    spLog->info("Step 6: GitRepoManager initialized");

    auto depEngine = std::make_unique<dns::core::DeploymentEngine>(
        *deEngine, *veEngine, *zrRepo, *vrRepo, *rrRepo, *prRepo,
        *drRepo, *arRepo, upGitRepoManager.get(), cfgApp.iDeploymentRetentionCount);
    auto reEngine = std::make_unique<dns::core::RollbackEngine>(*drRepo, *rrRepo, *arRepo);
    spLog->info("Step 9: Core engines initialized "
                "(VariableEngine, DiffEngine, DeploymentEngine, RollbackEngine)");

    // Schedule sync-check maintenance task (requires DiffEngine from Step 9)
    if (cfgApp.iSyncCheckInterval > 0) {
      msScheduler->schedule("sync-check",
          std::chrono::seconds(cfgApp.iSyncCheckInterval),
          [&zrRepo = *zrRepo, &deEngine = *deEngine]() {
            auto spLog = dns::common::Logger::get();
            auto vZones = zrRepo.listAll();
            int iChecked = 0;
            for (const auto& zone : vZones) {
              std::string sStatus = "in_sync";
              try {
                auto preview = deEngine.preview(zone.iId);
                sStatus = preview.bHasDrift ? "drift" : "in_sync";
              } catch (...) {
                sStatus = "error";
              }
              zrRepo.updateSyncStatus(zone.iId, sStatus);
              ++iChecked;
            }
            spLog->info("Sync check complete: {} zones checked", iChecked);
          });
    }

    // ── Step 10: Construct auth layer + route handlers ────────────────────
    auto amMiddleware = std::make_unique<dns::api::AuthMiddleware>(
        *upSigner, *srRepo, *akrRepo, *urRepo, *roleRepo,
        cfgApp.iJwtTtlSeconds, cfgApp.iApiKeyCleanupGraceSeconds);

    auto asService = std::make_unique<dns::security::AuthService>(
        *urRepo, *srRepo, *roleRepo, *upSigner,
        cfgApp.iJwtTtlSeconds, cfgApp.iSessionAbsoluteTtlSeconds);

    auto fedAuthService = std::make_unique<dns::security::FederatedAuthService>(
        *urRepo, *grRepo, *roleRepo, *srRepo, *upSigner,
        cfgApp.iJwtTtlSeconds, cfgApp.iSessionAbsoluteTtlSeconds);

    auto authRoutes = std::make_unique<dns::api::routes::AuthRoutes>(*asService, *amMiddleware, *urRepo);
    auto providerRoutes = std::make_unique<dns::api::routes::ProviderRoutes>(*prRepo, *amMiddleware);
    auto viewRoutes = std::make_unique<dns::api::routes::ViewRoutes>(*vrRepo, *amMiddleware);
    auto zoneRoutes = std::make_unique<dns::api::routes::ZoneRoutes>(*zrRepo, *amMiddleware, *deEngine);
    auto recordRoutes = std::make_unique<dns::api::routes::RecordRoutes>(
        *rrRepo, *zrRepo, *arRepo, *amMiddleware, *deEngine, *depEngine);
    auto variableRoutes = std::make_unique<dns::api::routes::VariableRoutes>(*varRepo, *amMiddleware);
    auto healthRoutes = std::make_unique<dns::api::routes::HealthRoutes>();
    auto themeRoutes = std::make_unique<dns::api::routes::ThemeRoutes>();
    auto deploymentRoutes = std::make_unique<dns::api::routes::DeploymentRoutes>(
        *drRepo, *rrRepo, *amMiddleware, *reEngine);
    auto auditRoutes = std::make_unique<dns::api::routes::AuditRoutes>(
        *arRepo, *amMiddleware, cfgApp.iAuditRetentionDays);
    auto userRoutes = std::make_unique<dns::api::routes::UserRoutes>(
        *urRepo, *grRepo, *amMiddleware);
    auto groupRoutes = std::make_unique<dns::api::routes::GroupRoutes>(*grRepo, *amMiddleware);
    auto roleRoutes = std::make_unique<dns::api::routes::RoleRoutes>(*roleRepo, *amMiddleware);
    auto apiKeyRoutes = std::make_unique<dns::api::routes::ApiKeyRoutes>(*akrRepo, *amMiddleware);
    auto settingsRoutes = std::make_unique<dns::api::routes::SettingsRoutes>(
        *settingsRepo, *amMiddleware, msScheduler.get());
    auto gitRepoRoutes = std::make_unique<dns::api::routes::GitRepoRoutes>(
        *gitRepoRepo, *amMiddleware, *upGitRepoManager);
    auto idpRoutes = std::make_unique<dns::api::routes::IdpRoutes>(
        *idpRepo, *amMiddleware, *oidcService, *samlService);
    auto oidcRoutes = std::make_unique<dns::api::routes::OidcRoutes>(
        *idpRepo, *oidcService, *fedAuthService);
    auto samlRoutes = std::make_unique<dns::api::routes::SamlRoutes>(
        *idpRepo, *samlService, *fedAuthService);

    crow::SimpleApp crowApp;
    auto apiServer = std::make_unique<dns::api::ApiServer>(
        crowApp, *authRoutes, *auditRoutes, *deploymentRoutes, *healthRoutes,
        *providerRoutes, *setupRoutes, *viewRoutes, *zoneRoutes, *recordRoutes,
        *variableRoutes);

    apiServer->registerRoutes();
    userRoutes->registerRoutes(crowApp);
    groupRoutes->registerRoutes(crowApp);
    roleRoutes->registerRoutes(crowApp);
    apiKeyRoutes->registerRoutes(crowApp);
    settingsRoutes->registerRoutes(crowApp);
    themeRoutes->registerRoutes(crowApp);
    gitRepoRoutes->registerRoutes(crowApp);
    idpRoutes->registerRoutes(crowApp);
    oidcRoutes->registerRoutes(crowApp);
    samlRoutes->registerRoutes(crowApp);

    // Serve static UI files (SPA fallback) — must be registered after API routes
    auto sfhHandler = std::make_unique<dns::api::StaticFileHandler>(cfgApp.sUiDir);
    if (!sSetupToken.empty()) {
      sfhHandler->setSetupToken(sSetupToken);
    }
    sfhHandler->registerRoutes(crowApp);

    spLog->info("Step 10: API routes registered");

    // ── Step 11: Start HTTP server ───────────────────────────────────────
    g_pApiServer = apiServer.get();
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    spLog->info("Step 11: Starting HTTP server on port {} ({} threads)",
                cfgApp.iHttpPort, cfgApp.iHttpThreads);

    // Step 12: Background task queue uses ThreadPool — ready
    spLog->info("Step 12: Background task queue ready (ThreadPool)");

    spLog->info("meridian-dns ready");

    // Blocks on Crow event loop until stop() is called
    apiServer->start(cfgApp.iHttpPort, cfgApp.iHttpThreads);

    // Graceful shutdown
    msScheduler->stop();
    spLog->info("MaintenanceScheduler stopped");
    spLog->info("meridian-dns shutdown complete");

    return EXIT_SUCCESS;
  } catch (const std::exception& ex) {
    std::cerr << "[fatal] startup failed: " << ex.what() << std::endl;
    // quick_exit avoids libpqxx static-destruction double-free (strconv.hxx:80)
    std::quick_exit(EXIT_FAILURE);
  }
}
