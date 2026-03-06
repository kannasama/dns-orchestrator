cmake_minimum_required(VERSION 3.20)
project(meridian-dns
  VERSION 0.1.0
  LANGUAGES CXX
  DESCRIPTION "Meridian DNS — Multi-Provider DNS Management"
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

# ── cpp-httplib (HTTP client for provider REST calls) ────────────────────
FetchContent_Declare(httplib
  GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
  GIT_TAG        v0.18.7
  GIT_SHALLOW    TRUE
)
set(HTTPLIB_REQUIRE_OPENSSL ON CACHE BOOL "" FORCE)
set(HTTPLIB_COMPILE OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(httplib)

# ── UI build (optional) ───────────────────────────────────────────────────
option(BUILD_UI "Build the Vue 3 web UI (requires Node.js)" ON)
if(BUILD_UI)
  find_program(NPM_EXECUTABLE npm REQUIRED)
  set(UI_SOURCE_DIR "${CMAKE_SOURCE_DIR}/ui")
  set(UI_BUILD_DIR "${UI_SOURCE_DIR}/dist")
  add_custom_target(ui-build ALL
    COMMAND ${NPM_EXECUTABLE} ci
    COMMAND ${NPM_EXECUTABLE} run build
    WORKING_DIRECTORY ${UI_SOURCE_DIR}
    COMMENT "Building Vue 3 web UI"
  )
  install(DIRECTORY ${UI_BUILD_DIR}/ DESTINATION share/meridian-dns/ui)
endif()

# ── Subdirectories ─────────────────────────────────────────────────────────
add_subdirectory(src)
add_subdirectory(tests)
