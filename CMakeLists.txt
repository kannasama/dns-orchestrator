cmake_minimum_required(VERSION 3.20)
project(dns-orchestrator
  VERSION 0.1.0
  LANGUAGES CXX
  DESCRIPTION "Multi-Provider DNS Orchestrator"
)

# ── C++20 Standard ──────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── Compiler warnings ──────────────────────────────────────────────────────
add_compile_options(-Wall -Wextra -Wpedantic -Werror)

# ── Export compile_commands.json for clangd / IDE integration ──────────────
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ── Dependency discovery ───────────────────────────────────────────────────
find_package(OpenSSL REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(spdlog REQUIRED)

include(FindPkgConfig)
pkg_check_modules(LIBPQXX REQUIRED IMPORTED_TARGET libpqxx)
pkg_check_modules(LIBGIT2 REQUIRED IMPORTED_TARGET libgit2)

# ── Crow (HTTP server) ──────────────────────────────────────────────────────
# Header-only; fetched at configure time — no system package required.
include(FetchContent)
FetchContent_Declare(
  Crow
  GIT_REPOSITORY https://github.com/CrowCpp/Crow.git
  GIT_TAG        v1.3.1
  GIT_SHALLOW    TRUE
)
set(CROW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(CROW_BUILD_TESTS    OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(Crow)

# ── Subdirectories ─────────────────────────────────────────────────────────
add_subdirectory(src)
add_subdirectory(tests)
