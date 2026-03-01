#include <atomic>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <thread>

#include "api/ApiServer.hpp"
#include "api/AuthMiddleware.hpp"
#include "common/Config.hpp"
#include "common/Logger.hpp"
#include "core/MaintenanceScheduler.hpp"
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
// Phase 2 implements steps 1-5. Phase 4 adds steps 6-8.
// Phase 5 adds steps 9-11.

int main() {
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

    // ── Step 6: GitOpsMirror — deferred to Phase 7 ────────────────────────
    spLog->warn("Step 6: GitOpsMirror — not yet implemented");

    // ── Step 7: ThreadPool — deferred to Phase 7 ──────────────────────────
    spLog->warn("Step 7: ThreadPool — not yet implemented");

    // ── Step 7a: Initialize MaintenanceScheduler ──────────────────────────
    auto urRepo = std::make_unique<dns::dal::UserRepository>(*cpPool);
    auto srRepo = std::make_unique<dns::dal::SessionRepository>(*cpPool);
    auto akrRepo = std::make_unique<dns::dal::ApiKeyRepository>(*cpPool);

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

    msScheduler->start();
    spLog->info("Step 7a: MaintenanceScheduler started (session flush every {}s, "
                "API key cleanup every {}s)",
                cfgApp.iSessionCleanupIntervalSeconds,
                cfgApp.iApiKeyCleanupIntervalSeconds);

    // ── Step 8: Initialize SamlReplayCache ────────────────────────────────
    auto srcCache = std::make_unique<dns::security::SamlReplayCache>();
    spLog->info("Step 8: SamlReplayCache initialized");

    // ── Step 9: ProviderFactory — deferred to Phase 6 ───────────────────────
    spLog->warn("Step 9: ProviderFactory — not yet implemented");

    // ── Step 10: Construct repositories and API routes ──────────────────────
    auto prRepo = std::make_unique<dns::dal::ProviderRepository>(*cpPool, *csService);
    auto vrRepo = std::make_unique<dns::dal::ViewRepository>(*cpPool);
    auto zrRepo = std::make_unique<dns::dal::ZoneRepository>(*cpPool);
    auto varRepo = std::make_unique<dns::dal::VariableRepository>(*cpPool);
    auto rrRepo = std::make_unique<dns::dal::RecordRepository>(*cpPool);
    auto drRepo = std::make_unique<dns::dal::DeploymentRepository>(*cpPool);
    auto arRepo = std::make_unique<dns::dal::AuditRepository>(*cpPool);

    auto asService = std::make_unique<dns::security::AuthService>(
        *urRepo, *srRepo, *upSigner,
        cfgApp.iJwtTtlSeconds, cfgApp.iSessionAbsoluteTtlSeconds);

    auto amMiddleware = std::make_unique<dns::api::AuthMiddleware>(
        *upSigner, *srRepo, *akrRepo, *urRepo,
        cfgApp.iJwtTtlSeconds, cfgApp.iApiKeyCleanupGraceSeconds);

    auto apiServer = std::make_unique<dns::api::ApiServer>(
        *asService, *amMiddleware,
        *prRepo, *vrRepo, *zrRepo, *varRepo, *rrRepo, *drRepo, *arRepo,
        cfgApp.iAuditRetentionDays);
    apiServer->registerRoutes();
    spLog->info("Step 10: API routes registered");

    // ── Step 11: Start HTTP server ──────────────────────────────────────────
    spLog->info("Step 11: Starting HTTP server on port {}", cfgApp.iHttpPort);

    // Run server in a separate thread so we can handle shutdown
    std::thread tServer([&]() {
      apiServer->start(cfgApp.iHttpPort, cfgApp.iHttpThreads);
    });

    // Wait for SIGINT/SIGTERM
    std::signal(SIGINT, [](int) {});
    std::signal(SIGTERM, [](int) {});
    sigset_t stSigSet;
    sigemptyset(&stSigSet);
    sigaddset(&stSigSet, SIGINT);
    sigaddset(&stSigSet, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &stSigSet, nullptr);
    int iSig = 0;
    sigwait(&stSigSet, &iSig);

    spLog->info("Received signal {}, shutting down...", iSig);
    apiServer->stop();
    tServer.join();

    // Graceful shutdown
    msScheduler->stop();
    spLog->info("MaintenanceScheduler stopped");
    spLog->info("dns-orchestrator shutdown complete");

    return EXIT_SUCCESS;
  } catch (const std::exception& ex) {
    std::cerr << "[fatal] startup failed: " << ex.what() << "\n";
    return EXIT_FAILURE;
  }
}
