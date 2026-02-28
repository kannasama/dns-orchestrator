# ── Google Test via FetchContent (pinned release) ───────────────────────────
include(FetchContent)
FetchContent_Declare(googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG        v1.14.0
)
# Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# ── Collect test sources ────────────────────────────────────────────────────
file(GLOB_RECURSE DNS_TEST_SOURCES
  "${CMAKE_CURRENT_SOURCE_DIR}/unit/*.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/integration/*.cpp"
)

# ── dns-tests executable ───────────────────────────────────────────────────
add_executable(dns-tests ${DNS_TEST_SOURCES})

target_link_libraries(dns-tests PRIVATE
  dns-core
  GTest::gtest
  GTest::gtest_main
  GTest::gmock
)

# ── CTest integration ──────────────────────────────────────────────────────
include(GoogleTest)
gtest_discover_tests(dns-tests)

# ── Integration test labeling ───────────────────────────────────────────────
# Integration tests require DNS_DB_URL to be set. Label them so they can be
# run selectively:
#   ctest --test-dir build -L Integration
#
# Individual integration tests are labeled via set_tests_properties() after
# gtest_discover_tests() populates them. Example:
#   set_tests_properties(ConnectionPoolTest.* PROPERTIES LABELS "Integration")
