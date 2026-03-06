# Phase 9 — Web UI (Vue 3 + TypeScript)

**Date:** 2026-03-05
**Status:** Design approved

---

## Overview

A Vue 3 + TypeScript web UI living in `ui/` within the main repository. In production, the
C++ backend (Crow) serves the built static files alongside the REST API. PrimeVue provides the
component library. Authentication uses JWT stored in `localStorage`.

**Design personality:** Precise, Reliable, Clean. An engineering-grade infrastructure tool that
prioritizes data density, predictable interactions, and operational confidence.

---

## Project Structure

```
ui/
├── package.json
├── vite.config.ts
├── tsconfig.json
├── index.html
├── .prettierrc              (2-space, single quotes, no semis)
├── src/
│   ├── main.ts
│   ├── App.vue
│   ├── router/
│   ├── stores/              (Pinia state management)
│   ├── api/                 (typed API client)
│   ├── components/
│   │   ├── layout/          (AppTopBar, AppSidebar, AppShell)
│   │   └── shared/          (ConfirmDeleteDialog, PageHeader, EmptyState)
│   ├── views/               (page-level components)
│   ├── composables/         (shared logic: useConfirm, useCrud, useRole)
│   ├── theme/               (PrimeVue theme preset + customization)
│   └── types/               (TypeScript interfaces)
├── public/
└── env.d.ts
```

**Key dependencies:** Vue 3, Vue Router, Pinia, PrimeVue (Aura preset), PrimeIcons,
TypeScript, Vite.

---

## Design System

### Theme Architecture

PrimeVue's styled mode with the **Aura** preset, configured with an **indigo** primary palette.
Theme customization uses PrimeVue's `definePreset()` API to override design tokens.

```
ui/src/theme/
├── preset.ts               (definePreset overrides on Aura)
└── index.ts                (exports configured theme for main.ts)
```

Dark mode is the default. Light mode is toggled via a button in the top bar. The preference
is persisted to `localStorage`. PrimeVue's `darkModeSelector` is set to a CSS class
(`.app-dark`) on `<html>`, toggled by the app.

Users can switch the accent color from a settings menu in the top bar user dropdown. Available
presets: indigo (default), blue, teal, green, amber, rose. This swaps the primary palette
via PrimeVue's `usePassThrough()` or by re-calling `definePreset()` at runtime.

### Color Tokens

| Role | Dark mode | Light mode | Usage |
|------|-----------|------------|-------|
| Surface background | `surface-950` | `surface-0` | Page background |
| Card / panel | `surface-900` | `surface-50` | Cards, sidebar, dialogs |
| Elevated surface | `surface-800` | `surface-100` | Table headers, hover states |
| Border | `surface-700` | `surface-200` | Dividers, card borders |
| Muted text | `surface-400` | `surface-500` | Secondary text, timestamps |
| Primary text | `surface-0` | `surface-900` | Body text |
| Primary accent | `indigo-400` | `indigo-600` | Buttons, links, active nav |
| Success | `green-400` | `green-600` | Adds, healthy status, deploy success |
| Warning | `amber-400` | `amber-600` | Modifications, drift indicators |
| Danger | `red-400` | `red-600` | Deletes, errors, unhealthy status |
| Info | `blue-400` | `blue-600` | Informational badges, tooltips |

### Typography

- **Body:** System font stack (`-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, ...`)
  — configured via PrimeVue's `fontFamily` token.
- **Monospace:** `'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace` — used for DNS
  record names, IP addresses, zone names, variable values, and API key hashes.
- **Scale:** PrimeVue defaults (14px base). No custom overrides needed.

### Spacing & Density

Dense layout optimized for data-heavy views:

- **Tables:** Compact row height (PrimeVue `size="small"` on DataTable).
- **Page padding:** `1.5rem` horizontal, `1rem` vertical.
- **Card gaps:** `1rem` between cards, `0.75rem` internal padding.
- **Form fields:** Standard PrimeVue spacing — no extra gaps.

### Iconography

PrimeIcons for all UI icons. Consistent icon usage:

| Context | Icon |
|---------|------|
| Providers | `pi-server` |
| Views | `pi-eye` |
| Zones | `pi-globe` |
| Records | `pi-list` |
| Variables | `pi-code` |
| Deployments | `pi-upload` |
| Audit | `pi-history` |
| Dashboard | `pi-home` |
| Add / Create | `pi-plus` |
| Edit | `pi-pencil` |
| Delete | `pi-trash` |
| Deploy / Push | `pi-play` |
| Rollback | `pi-undo` |
| Health OK | `pi-check-circle` |
| Health Degraded | `pi-exclamation-triangle` |
| Drift detected | `pi-exclamation-circle` |

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

Standalone full-page layout (no sidebar or top bar). Centered card on a `surface-950`
background. Meridian DNS wordmark above the form. Minimal — username, password, submit button.
Error messages appear inline below the form fields.

### App Shell (authenticated)

- **Top bar** — full width, `surface-900` background, subtle bottom border. Left side: app
  wordmark ("Meridian DNS") in primary accent color. Right side: theme toggle (sun/moon icon),
  accent color picker, user avatar/name with dropdown (role badge, logout).
- **Sidebar** — fixed left column, `surface-900` background, `14rem` wide. Nav items use
  PrimeIcons with labels. Active item highlighted with primary accent left border and
  tinted background. Hover state: subtle `surface-800` background. Items are grouped without
  section headers (the nav is short enough to not need them).
- **Main content area** — `surface-950` background, renders to the right of the sidebar.
  Each page has a consistent header: page title, optional subtitle, and action buttons
  (e.g., "Add Provider") right-aligned.

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
- **Role visibility:** The user's role is shown as a badge in the top bar user dropdown menu.
- **Server enforcement:** All authorization is enforced server-side. The UI is a convenience
  layer, not a security boundary.

---

## Core Pages

### Dashboard

Summary landing page with stat cards in a responsive grid (2-4 columns). Each card:
`surface-900` background, primary accent icon, large number, label. Stats: zone count, provider
count, recent deployments (last 24h), zones with drift. Below the cards: a compact recent
deployments table (last 10) and system health status from `GET /health`.

### Providers

DataTable with columns: name (monospace), type (badge), status. Compact rows. Admins see
Create/Edit/Delete actions — action buttons in a rightmost column, icon-only with tooltips.
Create/Edit form in a sidebar panel (PrimeVue `Drawer`): name, type dropdown, API URL, token
(password field, write-only — masked on display).

### Views

DataTable with columns: name, description, attached providers (shown as small PrimeVue `Tag`
components). Admins can create/edit views; edit form in a sidebar panel with a `MultiSelect`
for provider attachment.

### Zones

DataTable with columns: name (monospace), view name, record count. Clicking a zone row
navigates to a zone detail page. Detail page: zone metadata header, records in a sub-DataTable
(name, type, content, TTL — all monospace where appropriate). Records editable via modal dialog.
A "Deploy" button in the page header links to `/deployments?zones={id}`.

### Variables

DataTable with columns: name (monospace), value (monospace, truncated), scope (badge: global /
zone), zone name (if zone-scoped). Filtering by scope and zone via dropdowns above the table.
Form validates variable names against `^[a-zA-Z_][a-zA-Z0-9_]*$`.

### Audit Log

DataTable with columns: timestamp, user, action (badge), entity type, entity name, details
(truncated). Filters above the table: date range (PrimeVue `Calendar` range), entity type
dropdown, action dropdown, user search. Expanding a row shows full detail JSON. Toolbar actions:
NDJSON export button, admin-only purge button (with confirmation dialog and date input).

### Shared Patterns

- PrimeVue `DataTable` with `size="small"`, sorting, pagination (25/50/100 rows), and optional
  column filtering.
- Confirmation dialog (PrimeVue `ConfirmDialog`) before any delete action — red-tinted to
  signal danger.
- Toast notifications (PrimeVue `Toast`) for success/error feedback — bottom-right position,
  auto-dismiss after 4 seconds.
- Loading skeletons (PrimeVue `Skeleton`) while data fetches — match the shape of the expected
  content (table rows, cards).
- Empty states: centered icon + message + action button when a table has no data
  (e.g., "No providers yet. Add your first provider.").
- Page header component: title, optional description, right-aligned action slot.

---

## Deployments Page

Centralized hub for all deployment operations. The most critical page in the application —
designed for operational confidence with clear visual feedback at every step.

### Zone Selector

Multi-select dropdown (PrimeVue `MultiSelect`) with search, positioned at the top of the page.
One or more zones can be selected. When arriving from a zone's "Deploy" button, that zone is
pre-selected via route query parameter (e.g., `/deployments?zones=5`). A "Select All" option
is available for bulk operations.

### Preview & Deploy Panel

- **Preview** button calls `POST /zones/{id}/preview` for each selected zone (in parallel).
  A progress indicator shows while previews load.
- Results displayed **grouped by zone**, each in a collapsible panel (PrimeVue `Panel`):
  - Zone name as panel header with a summary badge (e.g., "3 adds, 1 modify, 2 deletes")
    using semantic colors.
  - Record-level change rows grouped by action, each with a colored left border:
    - **Add** (`green` left border) — new records with full details in monospace.
    - **Modify** (`amber` left border) — side-by-side or inline before → after diff for
      changed fields, with changed values highlighted.
    - **Delete** (`red` left border) — records to be removed, shown in muted text.
    - **Drift** (`amber` background tint + warning icon) — provider-side differences flagged
      prominently.
  - Zones with no changes show "In sync" with a `pi-check-circle` icon and are collapsed by
    default with de-emphasized header text.
- **Push All** button (primary accent, prominent) deploys all previewed zones with changes
  (sequentially to respect backend locking). Individual **Push** buttons per zone panel header
  allow selective deployment. Push buttons are disabled until preview completes.
- Confirmation dialog before push: "Deploy changes to N zones?" with a summary of total
  adds/modifies/deletes.
- During push: progress indicator per zone, status badges update in real-time (pending →
  deploying → success/failed).

### Deployment History

Below the deploy panel, separated by a visual divider. Single zone selected: shows that zone's
history. Multiple zones: merged timeline with zone column. DataTable columns: sequence number,
timestamp, status (badge), user, zone. Expanding a row shows the snapshot diff in the same
change-card format as the preview. Rollback button per deployment row with confirmation dialog.

---

## API Client & State Management

### API Client (`ui/src/api/`)

Thin typed wrapper around `fetch`. One module per resource:

- `client.ts` — base URL, JWT header injection, 401 redirect, error mapping to typed errors.
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
- `useThemeStore` — dark/light mode preference, accent color selection. Persists to
  `localStorage`.

Other data is fetched per-page on mount and managed locally. No global stores for CRUD
entities — avoids stale cache complexity. Stores can be added later if cross-page reactivity
is needed.

### TypeScript Types (`ui/src/types/`)

Interfaces matching API response shapes: `Provider`, `View`, `Zone`, `DnsRecord`, `Variable`,
`Deployment`, `AuditEntry`, `User`.

---

## Reusable Composables (`ui/src/composables/`)

- `useCrud<T>(apiModule)` — standard list/create/update/delete flow with loading state,
  error handling, and toast notifications. Returns `{ items, loading, fetch, create, update,
  remove }`. Used by all CRUD pages to avoid duplicating the same reactive pattern.
- `useConfirm(message)` — wraps PrimeVue's `useConfirm` with consistent dialog styling.
- `useRole()` — exposes `isAdmin`, `isOperator`, `isViewer` computed properties from
  `useAuthStore` for template `v-if` guards.
- `usePagination(defaults)` — manages page/pageSize/sort state synced with route query params.

---

## Accessibility

Best-effort WCAG AA compliance:

- All interactive elements are keyboard-navigable (PrimeVue handles this for its components).
- Focus-visible outlines use the primary accent color (`2px solid`).
- Color is never the sole indicator — badges include text labels, change types include icons
  alongside color coding.
- `prefers-reduced-motion`: disable transition animations when the OS preference is set.
- Semantic HTML: `<nav>`, `<main>`, `<header>`, `<table>` used appropriately in the app shell.
- ARIA labels on icon-only buttons (edit, delete, deploy actions).

---

## Implementation Order

Each step is a deliverable increment:

1. **Scaffold** — Vite + Vue 3 + TS + PrimeVue (Aura/indigo) + Router + Pinia. Theme preset
   with dark/light mode toggle. App shell (sidebar + top bar with accent color picker), login
   page, router guards, API client with auth, `useThemeStore`. CMake `BUILD_UI` flag, Crow
   static serving, Prettier config.
2. **Providers** — First CRUD page. Establishes reusable patterns: `useCrud` composable,
   DataTable config (small size, pagination, sorting), sidebar panel forms, confirmation
   dialogs, toast notifications, loading skeletons, empty states, page header component.
   Template for all subsequent pages.
3. **Views** — CRUD + provider attach/detach multi-select. Validates the reusable patterns
   established in step 2.
4. **Zones + Records** — Zone list → zone detail with records sub-table. Monospace rendering
   for DNS data. Modal form for record editing. "Deploy" link with query param.
5. **Variables** — CRUD with scope/zone filtering. Dropdown filters above the table.
6. **Deployments** — Multi-zone selector, batch preview with parallel API calls, change cards
   with semantic color-coded borders, push flow with progress indicators, deployment history
   with expandable diffs, rollback. Most complex page, built last so all supporting pages exist.
7. **Audit Log** — Filterable table with date range, entity type, action filters. Expandable
   detail rows. NDJSON export download, admin purge with confirmation.
8. **Dashboard** — Summary stat cards in responsive grid, recent deployments table, health
   status indicator. Aggregates from all sections.
