# Build Environment Setup — EndeavourOS / Arch Linux

> **Target Platform:** Linux (EndeavourOS) using `paru` as the AUR/Pacman helper.
> This guide sets up a complete native build environment for the C++ Multi-Provider DNS Orchestrator.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Install Build Tools](#2-install-build-tools)
3. [Install Library Dependencies](#3-install-library-dependencies)
4. [Install AUR Dependencies](#4-install-aur-dependencies)
5. [PostgreSQL Setup](#5-postgresql-setup)
6. [Clone the Repository](#6-clone-the-repository)
7. [Configure and Build](#7-configure-and-build)
8. [Verify the Build](#8-verify-the-build)
9. [Development Environment Variables](#9-development-environment-variables)
10. [Package Reference Table](#10-package-reference-table)

---

## 1. Prerequisites

Ensure `paru` is installed and your system is fully up to date before proceeding.

```bash
# Full system upgrade first — required to avoid partial-upgrade issues on Arch
paru -Syu
```

You will also need `base-devel` (provides `gcc`, `make`, `pkg-config`, etc.) and `git`:

```bash
paru -S --needed base-devel git
```

---

## 2. Install Build Tools

The project requires **CMake 3.20+**, **Ninja**, and **GCC 12+** (for C++20 support including
`std::jthread`, `std::format`, and `std::filesystem`).

```bash
paru -S --needed \
    cmake \
    ninja \
    gcc
```

> **Note:** EndeavourOS ships GCC 13+ in the standard repos. Verify with `gcc --version`.
> The minimum required is GCC 12 (`-std=c++20` with full `std::jthread` support).

---

## 3. Install Library Dependencies

All of the following are available in the official Arch/EndeavourOS repositories.

```bash
paru -S --needed \
    postgresql-libs \
    libpqxx \
    openssl \
    libgit2 \
    nlohmann-json \
    spdlog
```

> **Note:** `postgresql` (the server) is not listed here because this guide assumes an
> existing PostgreSQL 15+ instance is already running. Only the client library
> (`postgresql-libs`) is required to build and link against `libpq`.

### What each package provides

| Package | Provides | Used For |
|---------|----------|----------|
| `postgresql-libs` | `libpq.so`, `pg_config` | PostgreSQL C client library (runtime + headers) |
| `libpqxx` | `libpqxx.so`, `<pqxx/*.hxx>` | C++ PostgreSQL client (`libpqxx` DAL layer) |
| `openssl` | `libssl.so`, `libcrypto.so` | AES-256-GCM credential encryption, Argon2id hashing |
| `libgit2` | `libgit2.so`, `<git2.h>` | GitOps mirror subsystem (`libgit2` native bindings) |
| `nlohmann-json` | `<nlohmann/json.hpp>` | JSON serialization (header-only) |
| `spdlog` | `libspdlog.so`, `<spdlog/spdlog.h>` | Structured logging (JSON output, configurable levels) |

---

## 4. Install AUR Dependencies

The following libraries are not in the official repos and must be installed from the AUR.

### 4.1 Crow (HTTP Framework)

The API layer uses **Crow** (CrowCpp) for the HTTP server. Crow is acquired automatically via
CMake FetchContent at configure time — **no system package installation required**.

When you run `cmake -B build`, CMake downloads and configures Crow v1.3.1 from GitHub.
Nothing to install manually.

### 4.2 AUR Dependencies

There are no AUR dependencies. All third-party libraries are either in the official Arch
repos or acquired via CMake FetchContent at build time.

> **Note:** FTXUI is no longer required in this repository. The TUI client is maintained
> as a separate project — see [TUI Client Design](TUI_DESIGN.md).

### 4.4 Testing Framework (Google Test)

Google Test and Google Mock are pulled automatically via CMake `FetchContent` at configure
time. No system package is required.

```cmake
# Handled in tests/CMakeLists.txt — no manual install needed
FetchContent_Declare(googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG        v1.14.0)
FetchContent_MakeAvailable(googletest)
```

---

## 5. PostgreSQL Setup

The application requires **PostgreSQL 15+**. This section assumes you already have a
PostgreSQL instance running and accessible. If you need to install PostgreSQL from scratch,
see the [Arch Wiki — PostgreSQL](https://wiki.archlinux.org/title/PostgreSQL).

> **Version check:** Confirm your instance meets the minimum version requirement.
> ```bash
> psql --version
> # Expected: psql (PostgreSQL) 15.x or higher
> ```

### 5.1 Create the Development Database and User

Connect to your existing instance and provision the application database and role.

**If your instance uses peer authentication (local socket):**

```bash
sudo -u postgres psql <<'EOF'
CREATE USER dns WITH PASSWORD 'dns';
CREATE DATABASE dns_orchestrator OWNER dns;
GRANT ALL PRIVILEGES ON DATABASE dns_orchestrator TO dns;
EOF
```

**If your instance uses password authentication (TCP/IP):**

```bash
psql -h localhost -U postgres <<'EOF'
CREATE USER dns WITH PASSWORD 'dns';
CREATE DATABASE dns_orchestrator OWNER dns;
GRANT ALL PRIVILEGES ON DATABASE dns_orchestrator TO dns;
EOF
```

> **Existing user/database:** If the `dns` role or `dns_orchestrator` database already
> exist from a previous setup, skip the relevant `CREATE` statements and ensure the role
> has `ALL PRIVILEGES` on the database.

### 5.2 Verify Connectivity

Confirm the new role can connect before proceeding:

```bash
psql postgresql://dns:dns@localhost:5432/dns_orchestrator -c "SELECT version();"
```

A successful response confirms the connection string that goes into `DNS_DB_URL`.

### 5.3 Run Database Migrations

After building the project (see §7), apply the schema migrations in order:

```bash
psql postgresql://dns:dns@localhost:5432/dns_orchestrator \
    -f scripts/db/001_initial_schema.sql

psql postgresql://dns:dns@localhost:5432/dns_orchestrator \
    -f scripts/db/002_add_indexes.sql
```

> **Tip:** Migrations are numbered sequentially in `scripts/db/`. Run them in ascending
> numeric order. The application's `--migrate` flag (used in Docker) will automate this
> at runtime once implemented.

---

## 6. Clone the Repository

```bash
git clone <repository-url> dns-orchestrator
cd dns-orchestrator

# Initialize and update the workflow-orchestration skill submodule
git submodule update --init --recursive
```

> The `.gitmodules` file registers `.roo/skills/workflow-orchestration` as a submodule.
> The `--recursive` flag ensures it is checked out correctly.

---

## 7. Configure and Build

### 7.1 Configure with CMake

```bash
cmake -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_CXX_COMPILER=g++ \
    -DCMAKE_CXX_STANDARD=20
```

For a release build (optimized, no debug symbols):

```bash
cmake -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_COMPILER=g++ \
    -DCMAKE_CXX_STANDARD=20
```

### 7.2 Build

```bash
cmake --build build --parallel
```

The compiled binary will be located at `build/dns-orchestrator`.

### 7.3 Build with Verbose Output (Troubleshooting)

```bash
cmake --build build --parallel --verbose
```

---

## 8. Verify the Build

### 8.1 Check the Binary

```bash
./build/dns-orchestrator --version
```

### 8.2 Run Unit Tests

```bash
ctest --test-dir build --output-on-failure
```

### 8.3 Smoke Test Against Local PostgreSQL

Set the minimum required environment variables and start the server:

```bash
export DNS_DB_URL="postgresql://dns:dns@localhost:5432/dns_orchestrator"
export DNS_MASTER_KEY="$(openssl rand -hex 32)"
export DNS_JWT_SECRET="$(openssl rand -hex 32)"

./build/dns-orchestrator
```

The server should log `dns-orchestrator ready` and begin listening on port `8080`.

Verify the health endpoint:

```bash
curl -s http://localhost:8080/api/v1/health | python3 -m json.tool
# Expected: {"status":"ok"}
```

---

## 9. Development Environment Variables

Create a `.env` file in the project root for local development. **Do not commit this file.**

```bash
# .env — local development only
DNS_DB_URL=postgresql://dns:dns@localhost:5432/dns_orchestrator
DNS_DB_POOL_SIZE=5

# Generate once: openssl rand -hex 32
DNS_MASTER_KEY=<32-byte-hex-string>
DNS_JWT_SECRET=<32-byte-hex-string>

DNS_HTTP_PORT=8080
DNS_HTTP_THREADS=4
DNS_LOG_LEVEL=debug
DNS_AUDIT_STDOUT=true

# Optional: GitOps mirror (leave unset to disable)
# DNS_GIT_REMOTE_URL=git@github.com:yourorg/dns-mirror.git
# DNS_GIT_LOCAL_PATH=/tmp/dns-orchestrator-repo
# DNS_GIT_SSH_KEY_PATH=/home/youruser/.ssh/id_ed25519
```

Load the file in your shell session:

```bash
set -a && source .env && set +a
```

> **Security:** Add `.env` to `.gitignore` immediately. The `DNS_MASTER_KEY` encrypts all
> provider API tokens at rest — losing it makes stored credentials unrecoverable.

---

## 10. Package Reference Table

Complete mapping of Dockerfile/Debian package names to their Arch/AUR equivalents.

| Debian Package (Dockerfile) | Arch/AUR Package | Source | Notes |
|-----------------------------|------------------|--------|-------|
| `cmake` | `cmake` | Official | Build system |
| `ninja-build` | `ninja` | Official | Build backend |
| `gcc-12` / `g++-12` | `gcc` | Official | GCC 13+ ships by default; supports C++20 |
| `libpqxx-dev` | `libpqxx` | Official | C++ PostgreSQL client |
| `libssl-dev` | `openssl` | Official | OpenSSL 3.x headers + libs |
| `libgit2-dev` | `libgit2` | Official | libgit2 headers + libs |
| *(none)* | *(none)* | FetchContent | Crow HTTP framework (auto-fetched by CMake) |
| `nlohmann-json3-dev` | `nlohmann-json` | Official | Header-only JSON library |
| `postgresql` (runtime) | `postgresql` | Official | PostgreSQL 15+ server — **assumed pre-installed** |
| `libpq5` (runtime) | `postgresql-libs` | Official | PostgreSQL runtime client library |
| `libssl3` (runtime) | `openssl` | Official | OpenSSL 3.x runtime |
| `libgit2-1.5` (runtime) | `libgit2` | Official | libgit2 runtime |

---

## Quick-Start Summary

```bash
# 1. System update
paru -Syu

# 2. All dependencies in one shot
paru -S --needed \
    base-devel git cmake ninja gcc \
    postgresql-libs libpqxx \
    openssl libgit2 nlohmann-json \
    spdlog

# 3. Provision database on existing PostgreSQL 15+ instance
# (adjust connection method if your instance uses TCP/IP auth instead of peer auth)
sudo -u postgres psql -c "CREATE USER dns WITH PASSWORD 'dns';"
sudo -u postgres psql -c "CREATE DATABASE dns_orchestrator OWNER dns;"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE dns_orchestrator TO dns;"
# Verify: psql postgresql://dns:dns@localhost:5432/dns_orchestrator -c "SELECT version();"

# 4. Clone and initialize submodules
git clone <repository-url> dns-orchestrator && cd dns-orchestrator
git submodule update --init --recursive

# 5. Build
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_STANDARD=20
cmake --build build --parallel

# 6. Run migrations
psql postgresql://dns:dns@localhost:5432/dns_orchestrator -f scripts/db/001_initial_schema.sql
psql postgresql://dns:dns@localhost:5432/dns_orchestrator -f scripts/db/002_add_indexes.sql

# 7. Start
export DNS_DB_URL="postgresql://dns:dns@localhost:5432/dns_orchestrator"
export DNS_MASTER_KEY="$(openssl rand -hex 32)"
export DNS_JWT_SECRET="$(openssl rand -hex 32)"
./build/dns-orchestrator
```
