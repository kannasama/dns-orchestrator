#include <cstdlib>
#include <iostream>
#include <memory>
#include <stdexcept>

#include "common/Config.hpp"
#include "common/Logger.hpp"
#include "dal/ConnectionPool.hpp"
#include "security/CryptoService.hpp"
#include "security/HmacJwtSigner.hpp"
#include "security/IJwtSigner.hpp"

#include <openssl/crypto.h>

// Startup sequence from ARCHITECTURE.md §11.4
//
// Phase 2 implements steps 1-5. Steps 6-12 remain as stubs.

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

    // ── Steps 6-12: Deferred to future phases ────────────────────────────
    spLog->warn("Step 6: GitOpsMirror — not yet implemented");
    spLog->warn("Step 7: ThreadPool — not yet implemented");
    spLog->warn("Step 7a: MaintenanceScheduler — not yet implemented");
    spLog->warn("Step 8: SamlReplayCache — not yet implemented");
    spLog->warn("Step 9: ProviderFactory — not yet implemented");
    spLog->warn("Step 10: API routes — not yet implemented");
    spLog->warn("Step 11: HTTP server — not yet implemented");

    spLog->info("dns-orchestrator ready (foundation mode — API server not started)");

    return EXIT_SUCCESS;
  } catch (const std::exception& ex) {
    std::cerr << "[fatal] startup failed: " << ex.what() << "\n";
    return EXIT_FAILURE;
  }
}
