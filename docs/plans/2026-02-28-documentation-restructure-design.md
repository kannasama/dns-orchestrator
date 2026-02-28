# Documentation Restructure Design — DNS Orchestrator

> **Date:** 2026-02-28
> **Status:** Approved
> **Scope:** Consolidate documentation placement, populate README.md, create CODE_STANDARDS.md

---

## Table of Contents

1. [Overview](#1-overview)
2. [Current State](#2-current-state)
3. [Target State](#3-target-state)
4. [File Moves and Renames](#4-file-moves-and-renames)
5. [Cross-Reference Fixes](#5-cross-reference-fixes)
6. [README.md Content](#6-readmemd-content)
7. [CODE_STANDARDS.md](#7-code_standardsmd)
8. [Implementation Plan](#8-implementation-plan)

---

## 1. Overview

Documentation is scattered across the root directory, `docs/`, and `plans/` with inconsistent placement conventions. This design establishes a single convention: **README.md is the only documentation file at root**; everything else lives under `docs/`. The `tasks/` directory remains for operational artifacts.

---

## 2. Current State

| File | Location | Purpose |
|------|----------|---------|
| `README.md` | Root | **Empty** |
| `SPEC.md` | Root | High-level design specification |
| `ARCHITECTURE.md` | Root | Detailed system architecture |
| `docs/BUILD_ENVIRONMENT.md` | docs/ | Arch Linux build setup |
| `docs/TUI_DESIGN.md` | docs/ | TUI client design stub |
| `docs/plans/2026-02-28-project-framing-design.md` | docs/plans/ | Project framing and foundation plan |
| `plans/SECURITY_PLAN.md` | plans/ | Security hardening review |
| `tasks/lessons.md` | tasks/ | Lessons learned |
| `tasks/todo.md` | tasks/ | Task tracking |

**Inconsistencies:**
- Plans split across `plans/` and `docs/plans/`
- Root-level docs mixed with root project files
- Empty README provides no project entry point
- `docs/CODE_STANDARDS.md` was planned in the project framing design but never created

---

## 3. Target State

```
dns-orchestrator/
├── README.md                                          # Project entry point — only doc at root
├── docs/
│   ├── DESIGN.md                                      # Was SPEC.md (renamed + moved)
│   ├── ARCHITECTURE.md                                # Was root ARCHITECTURE.md (moved)
│   ├── BUILD_ENVIRONMENT.md                           # Unchanged location
│   ├── CODE_STANDARDS.md                              # NEW — extracted from project framing §5
│   ├── TUI_DESIGN.md                                  # Unchanged location
│   └── plans/
│       ├── 2026-02-28-project-framing-design.md       # Unchanged location
│       ├── 2026-02-28-documentation-restructure-design.md  # This document
│       └── SECURITY_PLAN.md                           # Was plans/SECURITY_PLAN.md (moved)
├── tasks/
│   ├── lessons.md                                     # Unchanged
│   └── todo.md                                        # Unchanged
```

**Principles:**
- Root has exactly one doc: `README.md`
- `docs/` holds all project documentation
- `docs/plans/` holds all pre-implementation plans and design documents
- `tasks/` remains for operational artifacts (not project documentation)

---

## 4. File Moves and Renames

| Operation | Source | Destination |
|-----------|--------|-------------|
| Move | `ARCHITECTURE.md` | `docs/ARCHITECTURE.md` |
| Move + Rename | `SPEC.md` | `docs/DESIGN.md` |
| Move | `plans/SECURITY_PLAN.md` | `docs/plans/SECURITY_PLAN.md` |
| Delete | `plans/` (empty directory) | — |
| Create | — | `docs/CODE_STANDARDS.md` |
| Rewrite | `README.md` | `README.md` (populated) |

**SPEC.md rename rationale:** The file serves as the high-level "what and why" document. `DESIGN.md` pairs naturally with `ARCHITECTURE.md` (Design = what, Architecture = how).

---

## 5. Cross-Reference Fixes

All internal links must be updated after file moves. Changes are listed per file.

### 5.1 docs/ARCHITECTURE.md (moved from root)

| Line | Old Reference | New Reference | Reason |
|------|---------------|---------------|--------|
| 3 | `[SPEC.md](SPEC.md)` | `[DESIGN.md](DESIGN.md)` | Renamed and now in same directory |
| 664 | `[TUI Client Design Document](docs/TUI_DESIGN.md)` | `[TUI Client Design Document](TUI_DESIGN.md)` | Now in same directory |

### 5.2 docs/plans/2026-02-28-project-framing-design.md

| Line | Old Reference | New Reference | Reason |
|------|---------------|---------------|--------|
| 7 | `[ARCHITECTURE.md](../../ARCHITECTURE.md)` | `[ARCHITECTURE.md](../ARCHITECTURE.md)` | ARCHITECTURE.md moved to docs/ |
| 7 | `[SECURITY_PLAN.md](../../plans/SECURITY_PLAN.md)` | `[SECURITY_PLAN.md](SECURITY_PLAN.md)` | SECURITY_PLAN.md moved to docs/plans/ (same directory) |

### 5.3 docs/TUI_DESIGN.md

| Line | Old Reference | New Reference | Reason |
|------|---------------|---------------|--------|
| 11 | `[ARCHITECTURE.md §6](../ARCHITECTURE.md)` | `[ARCHITECTURE.md §6](ARCHITECTURE.md)` | ARCHITECTURE.md moved to docs/ (same directory) |

### 5.4 docs/plans/SECURITY_PLAN.md (moved from plans/)

| Lines | Old Reference | New Reference | Reason |
|-------|---------------|---------------|--------|
| 5 | `[ARCHITECTURE.md](../ARCHITECTURE.md)` | `[ARCHITECTURE.md](../ARCHITECTURE.md)` | **No change** — `../` from docs/plans/ points to docs/ |
| 71, 94, 95, 136 | `../include/...` | `../../include/...` | Moved one directory deeper |

### 5.5 docs/BUILD_ENVIRONMENT.md

| Line | Old Reference | New Reference | Reason |
|------|---------------|---------------|--------|
| 110 | `[TUI Client Design](TUI_DESIGN.md)` | `[TUI Client Design](TUI_DESIGN.md)` | **No change** — same directory |

---

## 6. README.md Content

The README serves as the universal project entry point with these sections:

### 6.1 Title and Description

```markdown
# DNS Orchestrator

A high-performance DNS control plane built in C++ that serves as the single source of
truth for DNS records across multiple providers. Manages internal and external
infrastructure from a unified interface with split-horizon views, a variable template
engine, and GitOps-style version control.

> **Status:** Pre-implementation — architecture and design are complete;
> codebase scaffolding is in progress.
```

### 6.2 Key Features

- **Multi-Provider Management** — orchestrate DNS records across providers like PowerDNS, Cloudflare, and DigitalOcean through an extensible provider interface
- **Split-Horizon Views** — define internal and external views for the same domain, with strict isolation ensuring internal records never leak to external providers
- **Variable Template Engine** — store records with `{{var_name}}` placeholders; update a variable once and propagate to all affected records across all views
- **Preview-Before-Deploy Pipeline** — diff staged changes against live provider state, detect drift, and review before pushing
- **Deployment Snapshots and Rollback** — every push captures a full zone snapshot; roll back to any previous state (full zone or cherry-picked records)
- **GitOps Mirror** — after every deployment, the expanded zone state is committed to a Git repository as a human-readable backup
- **Audit Trail** — every mutation logged with before/after state, actor identity, and authentication method
- **Enterprise Authentication** — local accounts, OIDC, SAML 2.0, and API keys with full RBAC (admin / operator / viewer)
- **Client Interfaces** — Web GUI for visual diff review and variable management; separate TUI client (FTXUI) for keyboard-driven terminal workflows

### 6.3 Tech Stack

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

### 6.4 Documentation Index

| Document | Description |
|----------|-------------|
| [Design](docs/DESIGN.md) | High-level design specification — goals, concepts, and constraints |
| [Architecture](docs/ARCHITECTURE.md) | Detailed system architecture — components, interfaces, data models, API contracts |
| [Build Environment](docs/BUILD_ENVIRONMENT.md) | Development environment setup for Arch Linux / EndeavourOS |
| [Code Standards](docs/CODE_STANDARDS.md) | Naming conventions, formatting, error handling, and ownership rules |
| [TUI Design](docs/TUI_DESIGN.md) | Terminal UI client design (maintained in a separate repository) |
| [Security Plan](docs/plans/SECURITY_PLAN.md) | Pre-implementation security review — threat model, findings, and hardening decisions |
| [Project Framing](docs/plans/2026-02-28-project-framing-design.md) | Project skeleton and foundation layer implementation plan |

### 6.5 Quick Start

Reference to `docs/BUILD_ENVIRONMENT.md` with a condensed one-liner block:

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

### 6.6 Project Layout

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

---

## 7. CODE_STANDARDS.md

Extract section 5 ("Code Standards") from `docs/plans/2026-02-28-project-framing-design.md` into a standalone `docs/CODE_STANDARDS.md`. This includes:

- §5.1 Naming Conventions
- §5.2 Hungarian Notation Prefix Table
- §5.3 Class Abbreviations
- §5.4 Formatting and Style
- §5.5 Error Handling
- §5.6 Ownership and Pointers

The project framing document retains its full content (the standards section stays there as historical context). `CODE_STANDARDS.md` becomes the canonical, living reference that is maintained going forward.

---

## 8. Implementation Plan

Tasks in execution order. Each is independently completable.

1. **Move `ARCHITECTURE.md` → `docs/ARCHITECTURE.md`** and fix cross-references (SPEC.md→DESIGN.md, docs/TUI_DESIGN.md→TUI_DESIGN.md)
2. **Move `SPEC.md` → `docs/DESIGN.md`** (rename)
3. **Move `plans/SECURITY_PLAN.md` → `docs/plans/SECURITY_PLAN.md`** and fix cross-references (../include/ → ../../include/)
4. **Remove empty `plans/` directory**
5. **Fix cross-references in `docs/plans/2026-02-28-project-framing-design.md`** (../../ARCHITECTURE.md → ../ARCHITECTURE.md, ../../plans/SECURITY_PLAN.md → SECURITY_PLAN.md)
6. **Fix cross-references in `docs/TUI_DESIGN.md`** (../ARCHITECTURE.md → ARCHITECTURE.md)
7. **Create `docs/CODE_STANDARDS.md`** — extract from project framing design §5
8. **Populate `README.md`** with content defined in §6
9. **Verify all internal doc links** are correct after all moves
