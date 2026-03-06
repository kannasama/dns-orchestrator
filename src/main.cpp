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
#include "api/routes/AuthRoutes.hpp"
#include "api/routes/HealthRoutes.hpp"
#include "api/routes/ProviderRoutes.hpp"
#include "api/routes/RecordRoutes.hpp"
#include "api/routes/VariableRoutes.hpp"
#include "api/routes/ViewRoutes.hpp"
#include "api/routes/ZoneRoutes.hpp"
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
#include "gitops/GitOpsMirror.hpp"
#include "dal/ApiKeyRepository.hpp"
#include "dal/AuditRepository.hpp"
#include "dal/ConnectionPool.hpp"
#include "dal/DeploymentRepository.hpp"
#include "dal/ProviderRepository.hpp"
#include "dal/RecordRepository.hpp"
#include "dal/SessionRepository.hpp"
#include "dal/UserRepository.hpp"
#include "dal/VariableRepository.hpp"
#include "dal/ViewRepository.hpp"
#include "dal/ZoneRepository.hpp"
#include "security/AuthService.hpp"
#include "security/CryptoService.hpp"
#include "security/HmacJwtSigner.hpp"
#include "security/IJwtSigner.hpp"
#include "security/SamlReplayCache.hpp"

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
            << "  --help       Show this help message and exit\n"
            << "  --version    Show version information and exit\n"
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

    // ── Step 6: GitOpsMirror pointer (initialized after engines in Step 9) ─
    std::unique_ptr<dns::gitops::GitOpsMirror> upGitMirror;
    spLog->info("Step 6: GitOpsMirror deferred until engines ready");

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

    // ── Step 8: Initialize SamlReplayCache ────────────────────────────────
    auto srcCache = std::make_unique<dns::security::SamlReplayCache>();
    spLog->info("Step 8: SamlReplayCache initialized");

    // ── Step 9: Core engines ─────────────────────────────────────────────
    auto veEngine = std::make_unique<dns::core::VariableEngine>(*varRepo);
    auto deEngine = std::make_unique<dns::core::DiffEngine>(
        *zrRepo, *vrRepo, *rrRepo, *prRepo, *veEngine);

    // ── Step 6 (deferred): Initialize GitOpsMirror now that engines are ready ─
    if (cfgApp.oGitRemoteUrl.has_value() && !cfgApp.oGitRemoteUrl->empty()) {
      upGitMirror = std::make_unique<dns::gitops::GitOpsMirror>(
          *zrRepo, *vrRepo, *rrRepo, *veEngine);
      upGitMirror->initialize(*cfgApp.oGitRemoteUrl, cfgApp.sGitLocalPath);
      upGitMirror->pull();
      spLog->info("Step 6: GitOpsMirror initialized (remote={}, local={})",
                  *cfgApp.oGitRemoteUrl, cfgApp.sGitLocalPath);
    } else {
      spLog->info("Step 6: GitOpsMirror disabled (DNS_GIT_REMOTE_URL not set)");
    }

    auto depEngine = std::make_unique<dns::core::DeploymentEngine>(
        *deEngine, *veEngine, *zrRepo, *vrRepo, *rrRepo, *prRepo,
        *drRepo, *arRepo, upGitMirror.get(), cfgApp.iDeploymentRetentionCount);
    auto reEngine = std::make_unique<dns::core::RollbackEngine>(*drRepo, *rrRepo, *arRepo);
    spLog->info("Step 9: Core engines initialized "
                "(VariableEngine, DiffEngine, DeploymentEngine, RollbackEngine)");

    // ── Step 10: Construct auth layer + route handlers ────────────────────
    auto amMiddleware = std::make_unique<dns::api::AuthMiddleware>(
        *upSigner, *srRepo, *akrRepo, *urRepo,
        cfgApp.iJwtTtlSeconds, cfgApp.iApiKeyCleanupGraceSeconds);

    auto asService = std::make_unique<dns::security::AuthService>(
        *urRepo, *srRepo, *upSigner,
        cfgApp.iJwtTtlSeconds, cfgApp.iSessionAbsoluteTtlSeconds);

    auto authRoutes = std::make_unique<dns::api::routes::AuthRoutes>(*asService, *amMiddleware);
    auto providerRoutes = std::make_unique<dns::api::routes::ProviderRoutes>(*prRepo, *amMiddleware);
    auto viewRoutes = std::make_unique<dns::api::routes::ViewRoutes>(*vrRepo, *amMiddleware);
    auto zoneRoutes = std::make_unique<dns::api::routes::ZoneRoutes>(*zrRepo, *amMiddleware);
    auto recordRoutes = std::make_unique<dns::api::routes::RecordRoutes>(
        *rrRepo, *amMiddleware, *deEngine, *depEngine);
    auto variableRoutes = std::make_unique<dns::api::routes::VariableRoutes>(*varRepo, *amMiddleware);
    auto healthRoutes = std::make_unique<dns::api::routes::HealthRoutes>();
    auto deploymentRoutes = std::make_unique<dns::api::routes::DeploymentRoutes>(
        *drRepo, *rrRepo, *amMiddleware, *reEngine);
    auto auditRoutes = std::make_unique<dns::api::routes::AuditRoutes>(
        *arRepo, *amMiddleware, cfgApp.iAuditRetentionDays);

    crow::SimpleApp crowApp;
    auto apiServer = std::make_unique<dns::api::ApiServer>(
        crowApp, *authRoutes, *auditRoutes, *deploymentRoutes, *healthRoutes,
        *providerRoutes, *viewRoutes, *zoneRoutes, *recordRoutes, *variableRoutes);

    apiServer->registerRoutes();

    // Serve static UI files (SPA fallback) — must be registered after API routes
    auto sfhHandler = std::make_unique<dns::api::StaticFileHandler>(cfgApp.sUiDir);
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
