# DNS Orchestrator

A high-performance DNS control plane built in C++ that serves as the single source of truth for DNS records across multiple providers. Manages internal and external infrastructure from a unified interface with split-horizon views, a variable template engine, and GitOps-style version control.

> **Status:** Pre-implementation — architecture and design are complete; codebase scaffolding is in progress.

---

## Key Features

- **Multi-Provider Management** — orchestrate DNS records across providers like PowerDNS, Cloudflare, and DigitalOcean through an extensible provider interface
- **Split-Horizon Views** — define internal and external views for the same domain, with strict isolation ensuring internal records never leak to external providers
- **Variable Template Engine** — store records with `{{var_name}}` placeholders; update a variable once and propagate to all affected records across all views
- **Preview-Before-Deploy Pipeline** — diff staged changes against live provider state, detect drift, and review before pushing
- **Deployment Snapshots and Rollback** — every push captures a full zone snapshot; roll back to any previous state (full zone or cherry-picked records)
- **GitOps Mirror** — after every deployment, the expanded zone state is committed to a Git repository as a human-readable backup
- **Audit Trail** — every mutation logged with before/after state, actor identity, and authentication method
- **Enterprise Authentication** — local accounts, OIDC, SAML 2.0, and API keys with full RBAC (admin / operator / viewer)
- **Client Interfaces** — Web GUI for visual diff review and variable management; separate TUI client (FTXUI) for keyboard-driven terminal workflows

## Tech Stack

| Component | Technology |
|-----------|------------|
| Language | C++ (C++20, GCC 12+) |
| Build System | CMake 3.20+ / Ninja |
| HTTP Server | Restbed |
| Database | PostgreSQL 15+ (via libpqxx) |
| Encryption | OpenSSL 3.x (AES-256-GCM) |
| Serialization | nlohmann/json |
| Version Control | libgit2 |
| Logging | spdlog |
| Testing | Google Test / Google Mock |

## Documentation

| Document | Description |
|----------|-------------|
| [Design](docs/DESIGN.md) | High-level design specification — goals, concepts, and constraints |
| [Architecture](docs/ARCHITECTURE.md) | Detailed system architecture — components, interfaces, data models, API contracts |
| [Build Environment](docs/BUILD_ENVIRONMENT.md) | Development environment setup for Arch Linux / EndeavourOS |
| [Code Standards](docs/CODE_STANDARDS.md) | Naming conventions, formatting, error handling, and ownership rules |
| [TUI Design](docs/TUI_DESIGN.md) | Terminal UI client design (maintained in a separate repository) |
| [Security Plan](docs/plans/SECURITY_PLAN.md) | Pre-implementation security review — threat model, findings, and hardening decisions |
| [Project Framing](docs/plans/2026-02-28-project-framing-design.md) | Project skeleton and foundation layer implementation plan |

## Quick Start

See [Build Environment](docs/BUILD_ENVIRONMENT.md) for the full setup guide.

```bash
# Install dependencies (Arch Linux / EndeavourOS)
paru -S --needed \
    base-devel git cmake ninja gcc \
    postgresql-libs libpqxx \
    openssl libgit2 nlohmann-json \
    spdlog restbed

# Build
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_STANDARD=20
cmake --build build --parallel

# Run tests
ctest --test-dir build --output-on-failure
```

## Project Layout

```
dns-orchestrator/
├── include/          # Public headers organized by layer
├── src/              # Implementation files organized by layer
├── tests/            # Unit and integration tests
├── scripts/          # Database migrations and Docker entrypoint
├── docs/             # All project documentation
│   └── plans/        # Design documents and implementation plans
└── tasks/            # Operational tracking (lessons, todos)
```
