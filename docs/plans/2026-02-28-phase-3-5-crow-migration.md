# Phase 3.5: HTTP Library Migration (Restbed → Crow) Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the dormant Restbed HTTP library with Crow (CrowCpp) across the build system and
documentation, with zero changes to application source code.

**Architecture:** Crow is a header-only C++ HTTP framework acquired via CMake FetchContent — no
system package required. All API code is currently stubs with zero restbed type references, so
this is a pure build-system and documentation change. The 38 existing unit tests must continue to
pass unchanged.

**Tech Stack:** CMake FetchContent, CrowCpp v1.3.1

---

### Task 1: Replace restbed with Crow in the CMake build system

**Files:**
- Modify: `CMakeLists.txt:24-37`
- Modify: `src/CMakeLists.txt:19-31`

**Step 1: Confirm the current state**

```bash
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug 2>&1 | grep -i restbed
```

Expected: a warning line containing `"restbed not found via pkg-config"`.
This confirms the old dependency is visible before the change.

**Step 2: Update root `CMakeLists.txt`**

Replace the entire restbed block (lines 28–37). The old block is:

```cmake
# Restbed: optional — the AUR package is currently broken.
# When available, install via system package or build from source.
# The skeleton compiles without it since stubs don't reference restbed APIs.
pkg_check_modules(RESTBED IMPORTED_TARGET restbed)
if(NOT RESTBED_FOUND)
  message(WARNING
    "restbed not found via pkg-config. "
    "API server stubs will compile but restbed integration is deferred. "
    "Install restbed or build from source when implementing the API layer.")
endif()
```

Replace with:

```cmake
# ── Crow (HTTP server) ──────────────────────────────────────────────────────
# Header-only; fetched at configure time — no system package required.
include(FetchContent)
FetchContent_Declare(
  Crow
  GIT_REPOSITORY https://github.com/CrowCpp/Crow.git
  GIT_TAG        v1.3.1
)
set(CROW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(CROW_BUILD_TESTS    OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(Crow)
```

**Step 3: Update `src/CMakeLists.txt`**

Replace the `target_link_libraries` block AND the trailing conditional restbed block (lines 19–31).

Old (two separate blocks):

```cmake
target_link_libraries(dns-core PUBLIC
  PkgConfig::LIBPQXX
  OpenSSL::SSL
  OpenSSL::Crypto
  nlohmann_json::nlohmann_json
  spdlog::spdlog
  PkgConfig::LIBGIT2
)

# Link restbed only if found
if(RESTBED_FOUND)
  target_link_libraries(dns-core PUBLIC PkgConfig::RESTBED)
endif()
```

Replace with one block:

```cmake
target_link_libraries(dns-core PUBLIC
  PkgConfig::LIBPQXX
  OpenSSL::SSL
  OpenSSL::Crypto
  nlohmann_json::nlohmann_json
  spdlog::spdlog
  PkgConfig::LIBGIT2
  Crow::Crow
)
```

**Step 4: Clear the cache and reconfigure**

```bash
rm -rf build
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
```

Expected: CMake output includes lines about Crow being populated/configured (FetchContent
progress). No warning about restbed.

Verify no restbed reference in cmake output:

```bash
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug 2>&1 | grep -i restbed
```

Expected: empty (no output).

**Step 5: Build**

```bash
cmake --build build --parallel
```

Expected: Succeeds with 0 errors. Crow is header-only so no separate compilation step for it.

**Step 6: Run all tests**

```bash
ctest --test-dir build --output-on-failure
```

Expected: `38 tests passed, 0 tests failed`.

**Step 7: Commit**

```bash
git add CMakeLists.txt src/CMakeLists.txt
git commit -m "build: replace restbed with Crow (CrowCpp v1.3.1) via FetchContent

Restbed is dormant (last release Aug 2021), has no FetchContent support,
and has GCC 15 compatibility issues. Crow replaces it: header-only,
FetchContent-compatible, actively maintained (Feb 2026).

No application source changes — all API code remains stubs with zero
HTTP library type references. All 38 unit tests continue to pass."
```

---

### Task 2: Update `include/api/ApiServer.hpp` class comment

**Files:**
- Modify: `include/api/ApiServer.hpp:8`

**Step 1: Update line 8**

Current:
```cpp
/// Owns the Restbed Service instance; registers all routes at startup.
```

Replace with:
```cpp
/// Owns the Crow application instance; registers all routes at startup.
```

**Step 2: Verify build still passes**

```bash
cmake --build build --parallel
```

Expected: No errors.

**Step 3: Commit**

```bash
git add include/api/ApiServer.hpp
git commit -m "docs: update ApiServer comment — Crow replaces Restbed"
```

---

### Task 3: Update `docs/BUILD_ENVIRONMENT.md`

**Files:**
- Modify: `docs/BUILD_ENVIRONMENT.md`

Four distinct edits. Make them all before committing.

**Step 1: Replace §4.1 — Restbed section**

Find this exact block (starting at line 92):

```
### 4.1 Restbed (HTTP Server Framework)

The API layer uses **Restbed** (`librestbed`) for the asynchronous HTTP server.

```bash
paru -S restbed
```

> **AUR package:** [`restbed`](https://aur.archlinux.org/packages/restbed)
> Installs `librestbed.so` and headers to `/usr/include/restbed`.
```

Replace with:

```
### 4.1 Crow (HTTP Framework)

The API layer uses **Crow** (CrowCpp) for the HTTP server. Crow is acquired automatically via
CMake FetchContent at configure time — **no system package installation required**.

When you run `cmake -B build`, CMake downloads and configures Crow v1.3.1 from GitHub.
Nothing to install manually.
```

**Step 2: Replace §4.2 — AUR one-liner**

Find:

```
### 4.2 One-liner for all AUR packages

```bash
paru -S restbed
```
```

Replace with:

```
### 4.2 AUR Dependencies

There are no AUR dependencies. All third-party libraries are either in the official Arch
repos or acquired via CMake FetchContent at build time.
```

**Step 3: Update the package reference table — build-time row**

Find:

```
| `librestbed-dev` | `restbed` | AUR | Restbed HTTP framework |
```

Replace with:

```
| *(none)* | *(none)* | FetchContent | Crow HTTP framework (auto-fetched by CMake) |
```

**Step 4: Update the package reference table — runtime row**

Find and delete this entire row (Crow is header-only; no runtime `.so` exists):

```
| `librestbed0` (runtime) | `restbed` | AUR | Restbed runtime |
```

**Step 5: Update the Quick-Start Summary paru command**

Find `restbed` as the last line of the paru install list in the Quick-Start Summary section:

```
    restbed
```

Delete that line entirely. If it was the only remaining item on its own line, also remove the
trailing backslash from the line above it.

**Step 6: Commit**

```bash
git add docs/BUILD_ENVIRONMENT.md
git commit -m "docs: update build env — Crow replaces Restbed, no AUR dependencies"
```

---

### Task 4: Update `docs/ARCHITECTURE.md`

**Files:**
- Modify: `docs/ARCHITECTURE.md`

Four edits. Make them all before committing.

**Step 1: Update §4.1 framework line (line 126)**

Find:
```
**Framework:** Restbed (via `librestbed`)
```

Replace with:
```
**Framework:** Crow (CrowCpp, via CMake FetchContent — no system package required)
```

**Step 2: Update ApiServer table entry (line 139)**

Find:
```
| `ApiServer` | `api/ApiServer.hpp` | Owns the `restbed::Service` instance; registers all routes at startup |
```

Replace with:
```
| `ApiServer` | `api/ApiServer.hpp` | Owns the Crow application instance; registers all routes at startup |
```

**Step 3: Update Dockerfile build stage (line ~1529)**

Find:
```
  librestbed-dev nlohmann-json3-dev \
```

Replace with:
```
  nlohmann-json3-dev \
```

Crow is header-only and fetched by CMake; no apt package is needed in the Docker build stage.

**Step 4: Update Dockerfile runtime stage (line ~1545)**

Find:
```
  libpq5 libssl3 libgit2-1.5 librestbed0 \
```

Replace with:
```
  libpq5 libssl3 libgit2-1.5 \
```

Crow is header-only; there is no `libcrow.so` runtime dependency.

**Step 5: Commit**

```bash
git add docs/ARCHITECTURE.md
git commit -m "docs: update architecture — Crow replaces Restbed in §4.1 and Dockerfile model"
```

---

### Task 5: Update `docs/DESIGN.md`

**Files:**
- Modify: `docs/DESIGN.md:9`

**Step 1: Update the tech stack entry**

Find (line 9):
```
- **REST API:** `Pistache` or `Restbed` (Asynchronous, non-blocking HTTP).
```

Replace with:
```
- **REST API:** `Crow` (CrowCpp v1.3.1, header-only, acquired via CMake FetchContent).
```

**Step 2: Commit**

```bash
git add docs/DESIGN.md
git commit -m "docs: update design doc — Crow replaces Restbed/Pistache in tech stack"
```

---

### Task 6: Final audit

**Step 1: Grep for any remaining restbed references**

```bash
grep -ri "restbed" . \
  --include="*.cpp" \
  --include="*.hpp" \
  --include="*.md" \
  --include="*.cmake" \
  --include="CMakeLists.txt" \
  --exclude-dir=build \
  --exclude-dir=.git
```

Expected: No output (zero matches).

If any matches appear — fix them and commit:

```bash
git add <file>
git commit -m "docs: remove remaining restbed reference in <file>"
```

**Step 2: Full clean build and test — final confirmation**

```bash
rm -rf build
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

Expected:
- Configure: Crow FetchContent progress visible; zero restbed warnings
- Build: 0 errors, 0 warnings (beyond existing baseline)
- Tests: `38 tests passed, 0 tests failed`

Phase 3.5 is complete. ✓
