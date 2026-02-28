# TUI Client Design — DNS Orchestrator

> **Status:** Stub — to be expanded when TUI development begins
> **Repository:** Separate (TBD)
> **Framework:** FTXUI (Functional Terminal User Interface for C++)

---

## Overview

The TUI client is a standalone terminal application that communicates with the DNS Orchestrator server exclusively via its REST API (see [ARCHITECTURE.md §6](ARCHITECTURE.md)). It has **no direct database access** and shares no code with the server binary.

This document will contain the full TUI design when development begins. The sections below capture the original design intent from the server architecture for reference.

---

## Authentication

- Uses API key authentication exclusively (`X-API-Key` header)
- No interactive login screen; key loaded at startup
- Key sources (in priority order):
  1. `DNS_TUI_API_KEY` environment variable
  2. `~/.config/dns-orchestrator/credentials` file (mode `0600`, line: `api_key=<value>`)
- On startup, validates key against `GET /api/v1/auth/me`
- On failure (absent, expired, revoked key), prints error to stderr and exits with code 1

---

## Screen Hierarchy

```
TuiApp
├── ApiKeyConfig              ← startup only: loads key, calls GET /auth/me, exits on failure
├── MainScreen
│   ├── ViewSwitcher          ← keystroke: Tab cycles through views
│   ├── ZoneListPane          ← left panel: zones in current view
│   ├── RecordTablePane       ← right panel: records for selected zone
│   │   ├── RecordEditModal        ← inline edit with Vim bindings
│   │   └── VariablePickerModal    ← autocomplete for {{var}} insertion
│   ├── DeploymentHistoryPane ← bottom panel: deployment snapshots
│   ├── PreviewScreen         ← full-screen diff view
│   └── StatusBar             ← current view, zone, user, last sync time
└── AuditLogScreen            ← scrollable audit log viewer
```

---

## Key Bindings

| Key | Action |
|-----|--------|
| `Tab` | Cycle between views |
| `j` / `k` | Navigate records up/down |
| `i` | Enter edit mode on selected record |
| `Esc` | Cancel edit / close modal |
| `p` | Open preview diff for current zone |
| `P` | Push desired state for current zone |
| `r` | Open deployment history for current zone |
| `?` | Show help overlay |
| `q` | Quit |

---

## Communication Model

- Stateless HTTP requests to the same REST API as the Web GUI
- Every request includes `X-API-Key: <raw_key>` header
- No session state maintained between requests
- Single code path for all mutations (TUI → API → Core Engine)

---

## Dependencies

| Library | Purpose |
|---------|---------|
| FTXUI | Terminal UI framework (screens, components, event loop) |
| libcurl or similar | HTTP client for REST API communication |
| nlohmann/json | JSON serialization/deserialization |

---

## TODO

- [ ] Define repository structure and build system
- [ ] Design HTTP client abstraction
- [ ] Detail component-level specifications
- [ ] Define error handling and offline behavior
- [ ] Plan testing strategy (mock API server)
