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
# Uses a custom main (test_main.cpp) that shuts down spdlog before exit
# to avoid static destruction order issues with the spdlog shared library.
add_executable(dns-tests
  ${DNS_TEST_SOURCES}
  "${CMAKE_CURRENT_SOURCE_DIR}/test_main.cpp"
)

target_link_libraries(dns-tests PRIVATE
  dns-core
  GTest::gtest
  GTest::gmock
)

# ── CTest integration ──────────────────────────────────────────────────────
# Use PRE_TEST discovery mode to defer test listing to ctest run time
include(GoogleTest)
gtest_discover_tests(dns-tests
  DISCOVERY_MODE PRE_TEST
)
