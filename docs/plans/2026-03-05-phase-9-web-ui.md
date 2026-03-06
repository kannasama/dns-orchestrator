# Phase 9 — Web UI (Vue 3 + TypeScript)

**Date:** 2026-03-05
**Status:** Design approved

---

## Overview

A Vue 3 + TypeScript web UI living in `ui/` within the main repository. In production, the
C++ backend (Crow) serves the built static files alongside the REST API. PrimeVue provides the
component library. Authentication uses JWT stored in `localStorage`.

---

## Project Structure

```
ui/
├── package.json
├── vite.config.ts
├── tsconfig.json
├── index.html
├── src/
│   ├── main.ts
│   ├── App.vue
│   ├── router/
│   ├── stores/          (Pinia state management)
│   ├── api/             (typed API client)
│   ├── components/
│   ├── views/           (page-level components)
│   ├── composables/     (shared logic)
│   └── types/           (TypeScript interfaces)
├── public/
└── env.d.ts
```

**Key dependencies:** Vue 3, Vue Router, Pinia, PrimeVue, TypeScript, Vite.

---

## Build Integration

### Development

- `cd ui && npm install && npm run dev` starts the Vite dev server on port 5173.
- `vite.config.ts` proxies `/api/v1/` to `localhost:8080`.
- Hot module replacement for instant feedback.

### Production (CMake + Docker)

- CMake gains a `BUILD_UI` option (default OFF).
- When ON, a custom command runs `npm run build` and copies output to a known location.
- The Dockerfile gains a `node:22-slim` build stage: `npm ci && npm run build`.
- The existing runtime stage copies `ui/dist/` assets to a path the binary serves.
- Crow serves static files at `/` with SPA history mode fallback (non-API, non-file routes
  return `index.html`).
- No new containers — the existing `app` service serves both API and UI.

---

## Layout & Navigation

### Login Page

Standalone full-page layout (no sidebar or top bar). On successful login, JWT is stored in
`localStorage` and the user is redirected to the Dashboard.

### App Shell (authenticated)

- **Top bar** — full width. App logo/name ("Meridian DNS") on the left. User avatar/name on
  the right with a dropdown menu showing: role badge, profile link, logout button.
- **Sidebar** — fixed left column. Nav items:
  - Dashboard
  - Providers
  - Views
  - Zones
  - Variables
  - Deployments
  - Audit Log
- **Main content area** — renders to the right of the sidebar.

### Router Guards

`beforeEach` guard checks for a valid JWT. If missing or expired, redirect to login. Role-based
route restrictions are not needed — the UI hides actions based on role; enforcement is server-side.

---

## Auth Flow

- **Login:** `POST /auth/local/login` → receive JWT → store in `localStorage` → redirect to
  Dashboard.
- **Session persistence:** JWT in `localStorage` survives page refreshes. On app init, the
  `useAuthStore` hydrates from storage and calls `GET /me` to validate the token.
- **Logout:** `POST /auth/local/logout` → clear `localStorage` → redirect to login.
- **401 handling:** The API client intercepts 401 responses, clears the JWT, and redirects to
  login.

---

## Role-Based UI Restrictions

Three roles: `admin`, `operator`, `viewer`.

- **Hidden elements:** Users with restricted access do not see actions they cannot perform
  (edit/delete buttons, deploy actions, etc.). Features are hidden, not disabled.
- **Role visibility:** The user's role is shown in the top bar user dropdown menu.
- **Server enforcement:** All authorization is enforced server-side. The UI is a convenience
  layer, not a security boundary.

---

## Core Pages

### Dashboard

Summary landing page with at-a-glance stats: zone count, recent deployments, zones with
detected drift, system health from `GET /health`.

### Providers

Table listing all providers (name, type, status). Admins see Create/Edit/Delete actions.
Edit form includes token field (write-only, masked on display).

### Views

Table listing views with attached providers shown as tags. Admins can create/edit views and
attach/detach providers via a multi-select in the edit form.

### Zones

Table listing zones (name, view, record count). Clicking a zone navigates to a zone detail
page showing records in a sub-table. Records are editable inline or via modal form. A "Deploy"
button redirects to the Deployments page with that zone pre-selected.

### Variables

Table with columns: name, value, scope, zone (if scoped). Form validates variable names
against allowed characters.

### Audit Log

Searchable, filterable table of audit entries. Filters: date range, entity type, action, user.
NDJSON export download via `GET /audit/export`. Admins see a purge action.

### Shared Patterns

- PrimeVue `DataTable` with sorting, pagination, and optional filtering.
- Confirmation dialog before any delete action.
- Toast notifications for success/error feedback.
- Loading skeletons while data fetches.

---

## Deployments Page

Centralized hub for all deployment operations.

### Zone Selector

Multi-select dropdown with search. One or more zones can be selected. When arriving from a
zone's "Deploy" button, that zone is pre-selected via route query parameter
(e.g., `/deployments?zones=5`). A "Select All" option is available for bulk operations.

### Preview & Deploy Panel

- **Preview** button calls `POST /zones/{id}/preview` for each selected zone (in parallel).
- Results displayed **grouped by zone**, each in a collapsible section:
  - Zone name as section header with summary badge (e.g., "3 adds, 1 modify, 2 deletes").
  - Record-level change cards grouped by action:
    - **Add** (green) — new records with full details.
    - **Modify** (yellow) — before → after for changed fields.
    - **Delete** (red) — records to be removed.
    - **Drift** — provider-side differences flagged with warning indicator.
  - Zones with no changes show "In sync" and are visually de-emphasized.
- **Push All** button deploys all previewed zones with changes (sequentially to respect
  backend locking). Individual **Push** buttons per zone section allow selective deployment.
- Confirmation dialog before push: "Deploy changes to N zones?"

### Deployment History

Below the deploy panel. Single zone selected: shows that zone's history. Multiple zones:
merged timeline with zone column. Columns: sequence number, timestamp, status, user.
Expanding a row shows the snapshot diff. Rollback button per deployment with confirmation.

---

## API Client & State Management

### API Client (`ui/src/api/`)

Thin typed wrapper around `fetch`. One module per resource:

- `client.ts` — base URL, JWT header injection, 401 redirect, error mapping.
- `auth.ts` — login, logout, me.
- `providers.ts` — CRUD.
- `views.ts` — CRUD + attach/detach.
- `zones.ts` — CRUD.
- `records.ts` — CRUD (nested under zones).
- `variables.ts` — CRUD.
- `deployments.ts` — preview, push, history, diff, rollback.
- `audit.ts` — query, export, purge.
- `health.ts` — status check.

### State Management (Pinia)

- `useAuthStore` — user info, JWT, role. Hydrates from `localStorage`, validates via
  `GET /me` on init.
- `useNotificationStore` — toast message queue.

Other data is fetched per-page on mount and managed locally. No global stores for CRUD
entities — avoids stale cache complexity. Stores can be added later if cross-page reactivity
is needed.

### TypeScript Types (`ui/src/types/`)

Interfaces matching API response shapes: `Provider`, `View`, `Zone`, `DnsRecord`, `Variable`,
`Deployment`, `AuditEntry`, `User`.

---

## Implementation Order

Each step is a deliverable increment:

1. **Scaffold** — Vite + Vue 3 + TS + PrimeVue + Router + Pinia. App shell (sidebar + top bar),
   login page, router guards, API client with auth. CMake `BUILD_UI` flag, Crow static serving.
2. **Providers** — First CRUD page. Establishes reusable patterns (DataTable, forms, dialogs,
   toasts, loading states). Template for all subsequent pages.
3. **Views** — CRUD + provider attach/detach multi-select.
4. **Zones + Records** — Zone list → zone detail with records sub-table. "Deploy" link.
5. **Variables** — CRUD with scope/zone filtering.
6. **Deployments** — Multi-zone selector, batch preview, change cards, push flow, history,
   rollback. Most complex page, built last so all supporting pages exist.
7. **Audit Log** — Filterable table, date range, NDJSON export, admin purge.
8. **Dashboard** — Summary stats, recent activity. Aggregates from all sections.
