/// Custom test entry point that explicitly shuts down spdlog and avoids
/// static destruction order issues with the spdlog shared library on
/// GCC 15 / glibc. Uses _exit() to skip atexit handlers that trigger
/// double-free in spdlog's shared library unload path.

#include <gtest/gtest.h>
#include <spdlog/spdlog.h>

#include <cstdlib>

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  int iResult = RUN_ALL_TESTS();

  // Explicitly shutdown spdlog before exit
  spdlog::drop_all();
  spdlog::shutdown();

  // Use _exit() to skip C++ static destructors that cause double-free
  // with spdlog shared library on GCC 15. All test results are already
  // printed; the exit code is what matters for CI.
  _exit(iResult);
}
