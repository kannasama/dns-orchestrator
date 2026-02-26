# Design Specification: C++ Multi-Provider DNS Orchestrator

## 1. Executive Summary
This application is a high-performance DNS Control Plane built in C++20. It serves as the absolute **Source of Truth** for DNS records across multiple providers (PowerDNS, Cloudflare, DigitalOcean). It introduces a **Split-Horizon View** architecture and an **Object/Variable Template Engine** to manage internal and external infrastructure from a single interface while maintaining strict GitOps versioning.

## 2. Technical Stack & Ecosystem
*   **Language Standard:** C++20 (utilizing `std::jthread` for background syncing, `std::filesystem` for Git management, and `std::format`).
*   **REST API:** `Pistache` or `Restbed` (Asynchronous, non-blocking HTTP).
*   **Database:** PostgreSQL 15+ (via `libpqxx`).
*   **Serialization:** `nlohmann/json` (Configured for 4-space indentation for Git readability).
*   **TUI Framework:** `FTXUI` (Functional Terminal User Interface).
*   **Encryption:** `OpenSSL 3.x` (AES-256-GCM) for provider credential isolation.
*   **Version Control:** `libgit2` (C-bindings for native Git operations).

## 3. Core Architectural Concepts

### 3.1 Split-Horizon Views (Multi-View)
The system decouples a "Zone" from a "Provider" by introducing a **View** abstraction layer.
*   **Logic:** A single domain (e.g., `internal.dev`) can exist in multiple views.
    *   **Internal View:** Targets on-premise PowerDNS instances.
    *   **External View:** Targets Cloudflare or DigitalOcean.
*   **Mapping:** 
    *   `View A` -> `[Provider 1, Provider 2]`
    *   `View B` -> `[Provider 3]`
*   **Integrity:** The system ensures records in the "Internal" view never leak to "External" provider APIs during a deployment.

### 3.2 Object & Variable Engine
To support Infrastructure-as-Code (IaC) patterns, the system implements a **Variable Registry**.
*   **Registry Scopes:**
    *   **Global:** Available to all zones (e.g., `NTP_SERVER = 10.0.0.5`).
    *   **Zone-Scoped:** Overrides or unique variables for a specific domain.
*   **Variable Types:**
    *   `IPv4/IPv6`: For A/AAAA records.
    *   `Target`: For CNAME/SRV/MX aliases.
*   **Reference Syntax:** Records are stored in the DB as `{{var_name}}`. The C++ engine performs a **Recursive Expansion** at the "Preview" stage to resolve the final values before transmission.

## 4. Storage & State Management

### 4.1 PostgreSQL (Operational State)
The schema is designed for relational integrity and RBAC readiness:
*   `providers`: Storage of API endpoints and encrypted tokens.
*   `variables`: K/V store for objects with type validation.
*   `views`: Definition of views and their associated provider IDs.
*   `zones`: The domain name linked to specific views.
*   `records`: The raw record data (storing variable placeholders).
*   `staging`: A "Pending" table for batch modifications.

### 4.2 GitOps Strategy (The "Mirror")
Upon a successful deployment (Push):
1.  The engine generates a **Fully Expanded JSON** representation of the zone.
2.  **File Path:** `/repo/{view_name}/{provider_name}/{zone_name}.json`.
3.  **Operation:** The system performs a `git add`, `git commit -m "Update by [User] via API"`, and `git push`.
4.  This ensures the Git repo is a human-readable backup of exactly what is live on the provider.

## 5. The Deployment Pipeline (Workflow)

### 5.1 Step 1: Staging & Variable Assignment
*   Users update records via the GUI/TUI.
*   The system validates that any variables used (e.g., `{{LB_VIP}}`) exist in the registry.
*   Changes are written to the `staging` table; no live infrastructure is touched.

### 5.2 Step 2: Preview (The Diff Engine)
*   The engine fetches the **Live State** from the target Provider API.
*   The engine fetches the **Staged State** and **Expands Variables**.
*   **Drift Detection:** It identifies any records existing on the provider that are *not* in the DB.
*   **Output:** A JSON/Textual diff showing: `Provider Value` vs. `Calculated Source-of-Truth Value`.

### 5.3 Step 3: Deployment (Push)
*   **Atomic Updates:** Updates are pushed to the Provider API.
*   **Anomalous Record Purge:** If Drift Detection is enabled, records not in the Source of Truth are deleted from the provider.
*   **Post-Push:** Git mirroring is triggered immediately.

## 6. Security & Governance
*   **Credential Security:** API Keys are encrypted at rest using a master key (provided via Environment Variable at runtime).
*   **Audit Logging:** 
    *   Every record change is logged with `Old Value`, `New Value`, `Variable Used`, and `Identity`.
    *   Logs are stored in PostgreSQL and optionally mirrored to `stdout` for Docker log collection.
*   **Identity:** Support for OIDC and SAML for enterprise SSO, alongside a local "Emergency Admin" account.

## 7. Client Interfaces

### 7.1 Web GUI
*   **Visual Diff:** Side-by-side comparison of current provider state vs. proposed state.
*   **Object Manager:** Interface to update a variable once and see all 50+ affected records across all views.

### 7.2 TUI (Terminal User Interface)
*   **Speed:** Direct keyboard navigation for rapid record updates.
*   **Context Aware:** Allows switching between "View" contexts (Internal vs. External) with a single keystroke.
*   **Vim Bindings:** Native-feeling text manipulation for record content.

## 8. Deployment Model
*   **Containerization:** Multi-stage `Dockerfile`.
    *   **Build Stage:** Includes `cmake`, `gcc-12+`, `libpqxx-dev`, `libssl-dev`.
    *   **Run Stage:** Minimal Debian/Alpine-based image containing only the binary and runtime libraries.
*   **Concurrency:** Utilizes a C++ thread pool to handle simultaneous "Previews" across different zones to prevent UI blocking.