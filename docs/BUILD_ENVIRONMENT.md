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
    nlohmann-json
```

### What each package provides

| Package | Provides | Used For |
|---------|----------|----------|
| `postgresql-libs` | `libpq.so`, `pg_config` | PostgreSQL C client library (runtime + headers) |
| `libpqxx` | `libpqxx.so`, `<pqxx/*.hxx>` | C++ PostgreSQL client (`libpqxx` DAL layer) |
| `openssl` | `libssl.so`, `libcrypto.so` | AES-256-GCM credential encryption, Argon2id hashing |
| `libgit2` | `libgit2.so`, `<git2.h>` | GitOps mirror subsystem (`libgit2` native bindings) |
| `nlohmann-json` | `<nlohmann/json.hpp>` | JSON serialization (header-only) |

---

## 4. Install AUR Dependencies

The following libraries are not in the official repos and must be installed from the AUR.

### 4.1 Restbed (HTTP Server Framework)

The API layer uses **Restbed** (`librestbed`) for the asynchronous HTTP server.

```bash
paru -S restbed
```

> **AUR package:** [`restbed`](https://aur.archlinux.org/packages/restbed)
> Installs `librestbed.so` and headers to `/usr/include/restbed`.

### 4.2 FTXUI (Terminal UI Framework)

The TUI layer uses **FTXUI** for the functional terminal interface.

```bash
paru -S ftxui
```

> **AUR package:** [`ftxui`](https://aur.archlinux.org/packages/ftxui)
> Installs `libftxui-*.a` static libraries and headers to `/usr/include/ftxui`.

### 4.3 One-liner for all AUR packages

```bash
paru -S restbed ftxui
```

---

## 5. PostgreSQL Setup

The application requires a running **PostgreSQL 15+** instance for local development.

### 5.1 Install PostgreSQL

```bash
paru -S postgresql
```

### 5.2 Initialize the Database Cluster

PostgreSQL on Arch requires manual cluster initialization before first use.

```bash
# Initialize the data directory as the postgres system user
sudo -u postgres initdb --locale=en_US.UTF-8 -D /var/lib/postgres/data
```

### 5.3 Enable and Start the Service

```bash
sudo systemctl enable --now postgresql
```

Verify it is running:

```bash
sudo systemctl status postgresql
```

### 5.4 Create the Development Database and User

```bash
sudo -u postgres psql <<'EOF'
CREATE USER dns WITH PASSWORD 'dns';
CREATE DATABASE dns_orchestrator OWNER dns;
GRANT ALL PRIVILEGES ON DATABASE dns_orchestrator TO dns;
EOF
```

### 5.5 Run Database Migrations

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
| `librestbed-dev` | `restbed` | AUR | Restbed HTTP framework |
| `nlohmann-json3-dev` | `nlohmann-json` | Official | Header-only JSON library |
| `libftxui-dev` | `ftxui` | AUR | FTXUI terminal UI framework |
| `postgresql` (runtime) | `postgresql` | Official | PostgreSQL 15+ server |
| `libpq5` (runtime) | `postgresql-libs` | Official | PostgreSQL runtime client library |
| `libssl3` (runtime) | `openssl` | Official | OpenSSL 3.x runtime |
| `libgit2-1.5` (runtime) | `libgit2` | Official | libgit2 runtime |
| `librestbed0` (runtime) | `restbed` | AUR | Restbed runtime |

---

## Quick-Start Summary

```bash
# 1. System update
paru -Syu

# 2. All dependencies in one shot
paru -S --needed \
    base-devel git cmake ninja gcc \
    postgresql postgresql-libs libpqxx \
    openssl libgit2 nlohmann-json \
    restbed ftxui

# 3. Initialize PostgreSQL
sudo -u postgres initdb --locale=en_US.UTF-8 -D /var/lib/postgres/data
sudo systemctl enable --now postgresql
sudo -u postgres psql -c "CREATE USER dns WITH PASSWORD 'dns';"
sudo -u postgres psql -c "CREATE DATABASE dns_orchestrator OWNER dns;"

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
