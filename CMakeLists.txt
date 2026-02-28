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

# ── Subdirectories ─────────────────────────────────────────────────────────
add_subdirectory(src)
add_subdirectory(tests)
