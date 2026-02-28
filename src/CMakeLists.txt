# ── dns-core static library ─────────────────────────────────────────────────
# All .cpp files under src/ except main.cpp
file(GLOB_RECURSE DNS_CORE_SOURCES
  "${CMAKE_CURRENT_SOURCE_DIR}/common/*.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/*.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/core/*.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/providers/*.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/dal/*.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/gitops/*.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/security/*.cpp"
)

add_library(dns-core STATIC ${DNS_CORE_SOURCES})

target_include_directories(dns-core PUBLIC
  "${PROJECT_SOURCE_DIR}/include"
)

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

# ── dns-orchestrator executable ─────────────────────────────────────────────
add_executable(dns-orchestrator main.cpp)

target_link_libraries(dns-orchestrator PRIVATE
  dns-core
)
