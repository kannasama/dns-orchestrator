# Design Specification: Multi-Provider DNS Orchestrator (C++)

## 1. Project Overview
A centralized, API-centric DNS management platform designed to provide a unified interface for disparate DNS providers (PowerDNS, Cloudflare, DigitalOcean). The system acts as the absolute **Source of Truth**, leveraging a dual-storage strategy (PostgreSQL + Git) to ensure operational speed, versioned history, and disaster recovery.

## 2. Design Philosophy
*   **Source of Truth:** All DNS records are managed within the application. Manual changes made at the provider level are considered "drift" and are overwritten by the application's state.
*   **Staged Deployment:** No change is pushed to a provider without a mandatory "Preview" (Dry Run) phase.
*   **GitOps Integration:** Every successful deployment is serialized to formatted JSON and committed/pushed to a remote Git repository automatically.

## 3. Technical Stack
*   **Language:** C++20 (utilizing `std::jthread`, `std::filesystem`, and `std::format`).
*   **API Framework:** `Pistache` or `Restbed` (Asynchronous RESTful JSON API).
*   **Database:** PostgreSQL (via `libpqxx`).
*   **JSON Engine:** `nlohmann/json` (Formatted output for Git readability).
*   **TUI Library:** `FTXUI` (Functional Terminal User Interface).
*   **Auth:** Local (PostgreSQL), LDAP, OIDC, and SAML integration.
*   **Security:** `OpenSSL` / `Botan` for AES-256-GCM encryption of provider API keys.
*   **Deployment:** Dockerized service (Multi-stage build).

## 4. Architectural Components

### 4.1 Storage Layer (Dual-Tier)
1.  **Operational DB (PostgreSQL):** 
    *   Stores active records, staged changes, user sessions, and encrypted provider credentials.
    *   Optimized for rapid API querying and GUI/TUI rendering.
2.  **Version Control (Git):**
    *   Each zone is stored as a pretty-printed (formatted) JSON file.
    *   Structure: `/repo/{provider_name}/{zone_name}.json`.
    *   Logic: Upon a successful "Push" to a provider, the system writes the JSON, performs a `git commit`, and immediately executes a `git push`.

### 4.2 Provider Abstraction (Adapter Pattern)
An extensible C++ interface (`IDNSProvider`) allows for easy addition of future providers (BIND, Microsoft DNS).
*   **Supported Features:** Standard records (A, AAAA, CNAME, MX, TXT, NS).
*   **Provider-Specifics:** Cloudflare `proxied` (orange cloud) boolean support.
*   **Drift Detection:** A "Sync/Refresh" module that compares provider state with the DB and identifies anomalies for the user to import or purge.

## 5. System Workflows

### 5.1 The Deployment Pipeline
1.  **Stage:** User edits records via Web GUI or TUI. Changes are stored in a `staging_area` table.
2.  **Preview (Mandatory):** 
    *   System fetches the live state from the Provider API.
    *   Calculates a `diff` against the `staging_area`.
    *   Presents the user with a "Proposed Changes" report.
3.  **Push:**
    *   Applies changes to the Provider API.
    *   If successful:
        *   Updates the `records` table in PostgreSQL.
        *   Serializes the new zone state to JSON.
        *   Commits and Pushes to the Git repository.

### 5.2 Security & Governance
*   **Key Management:** Provider API keys are encrypted with AES-256-GCM before storage. Keys are only decrypted in-memory during the Push process.
*   **Audit Logging:** Every interaction (Login, Edit, Preview, Push) is recorded in a tamper-evident `audit_log` table including User ID and Source IP.
*   **RBAC Framework:** Initial schema includes Role-Based Access Control hooks (Roles, Permissions, User-to-Zone mapping) to support future multi-tenancy.

## 6. Client Interface Requirements

### 6.1 Web-Based GUI
*   Visual dashboard for zone management.
*   Bulk record editing and import/export functionality.
*   Audit log viewer and deployment history.

### 6.2 TUI (Terminal User Interface)
*   Optimized for power users and quick edits.
*   Interactive record list with keyboard shortcuts.
*   Integrated "Vim-style" buffer editing for TXT/SPF records.
*   Direct access to the Stage -> Preview -> Push workflow.

## 7. Deployment & Environment
*   **Container:** Single Docker image containing the C++ binary and necessary shared libraries (`libpq`, `libssl`, `libgit2`).
*   **Volume Mounts:** Requires a mount for the Git repository workspace and SSH keys for Git authentication.
*   **Scalability:** Designed for low resource overhead, capable of managing hundreds of records with sub-second API response times.

## 8. Data Schema (Conceptual)
*   `zones`: id, provider_id, name, zone_type.
*   `records`: id, zone_id, type, name, content, ttl, is_proxied (CF), updated_at.
*   `staging`: id, user_id, zone_id, original_data, proposed_data, status.
*   `credentials`: provider_id, encrypted_key, iv, updated_at.
*   `audit_log`: id, timestamp, user_id, action, zone_id, metadata (JSON).