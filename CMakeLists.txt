cmake_minimum_required(VERSION 3.20)
project(nanonos VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(NANONOS_BUILD_TESTS "Build unit tests" ON)
option(NANONOS_BUILD_BENCH "Build benchmarks" ON)
option(NANONOS_BUILD_FUZZERS "Build libFuzzer targets (clang only)" OFF)
option(NANONOS_SANITIZE "Build with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(NANONOS_WERROR "Treat compiler warnings as errors" OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

if(MSVC)
  add_compile_options(/W4 /permissive- /Zc:__cplusplus /utf-8)
  add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX)
  if(NANONOS_WERROR)
    add_compile_options(/WX)
  endif()
else()
  add_compile_options(-Wall -Wextra -Wpedantic -Wshadow -Wnon-virtual-dtor)
  if(NANONOS_WERROR)
    add_compile_options(-Werror)
  endif()
  if(NANONOS_SANITIZE)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined)
    add_link_options(-fsanitize=address,undefined)
  endif()
endif()

# Core library: everything that does not touch the operating system. It builds
# on Linux, macOS and Windows, and CI runs its tests on x86-64, ARM64 and
# big-endian s390x.
add_library(nanonos_core STATIC
  src/common/hash.cc
  src/common/logging.cc
  src/common/status.cc
  src/common/types.cc
  src/packet/builder.cc
  src/packet/packet.cc
  src/asic/acl.cc
  src/asic/ecmp.cc
  src/asic/lpm.cc
  src/asic/qos.cc
  src/asic/vasic.cc
  src/sai/recorder.cc
  src/sai/sai.cc
  src/orch/config.cc
  src/orch/orchagent.cc
  src/proto/bgp_message.cc
  src/proto/bgp_speaker.cc
  src/proto/lldp.cc
  src/sw/switch_node.cc
)
target_include_directories(nanonos_core PUBLIC src)
if(NOT MSVC)
  # Google C++ style: no exceptions. Errors are reported with Status codes.
  target_compile_options(nanonos_core PRIVATE -fno-exceptions)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  add_library(nanonos_linux STATIC
    src/linux/af_packet_port.cc
    src/linux/cli_server.cc
    src/linux/event_loop.cc
    src/linux/netlink_monitor.cc
    src/linux/tap_device.cc
    src/linux/tcp_transport.cc
  )
  target_link_libraries(nanonos_linux PUBLIC nanonos_core)
  target_compile_options(nanonos_linux PRIVATE -fno-exceptions)

  add_executable(nanonosd src/tools/nanonosd.cc)
  target_link_libraries(nanonosd PRIVATE nanonos_linux)

  add_executable(nosctl src/tools/nosctl.cc)
  target_link_libraries(nosctl PRIVATE nanonos_core)
endif()

if(NANONOS_BUILD_TESTS)
  enable_testing()
  include(FetchContent)
  FetchContent_Declare(googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.15.2.tar.gz
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
  set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)

  add_executable(nanonos_tests
    tests/acl_test.cc
    tests/bgp_message_test.cc
    tests/bgp_speaker_test.cc
    tests/config_test.cc
    tests/ecmp_test.cc
    tests/fabric_sim_test.cc
    tests/fdb_test.cc
    tests/lldp_test.cc
    tests/lpm_test.cc
    tests/packet_test.cc
    tests/pipeline_test.cc
    tests/qos_test.cc
  )
  target_link_libraries(nanonos_tests PRIVATE nanonos_core GTest::gtest_main)
  add_test(NAME unit_tests COMMAND nanonos_tests)

  # Separate binary: it replaces global operator new to prove the forwarding
  # path performs no heap allocation per packet.
  add_executable(nanonos_alloc_test tests/alloc_test.cc)
  target_link_libraries(nanonos_alloc_test PRIVATE nanonos_core GTest::gtest_main)
  add_test(NAME alloc_test COMMAND nanonos_alloc_test)
endif()

if(NANONOS_BUILD_BENCH)
  add_executable(nanonos_bench bench/bench_main.cc)
  target_link_libraries(nanonos_bench PRIVATE nanonos_core)
endif()

if(NANONOS_BUILD_FUZZERS)
  if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "NANONOS_BUILD_FUZZERS requires clang (libFuzzer)")
  endif()
  foreach(fuzzer packet pipeline bgp lldp config)
    add_executable(fuzz_${fuzzer} fuzz/${fuzzer}_fuzzer.cc)
    target_link_libraries(fuzz_${fuzzer} PRIVATE nanonos_core)
    target_compile_options(fuzz_${fuzzer} PRIVATE -fsanitize=fuzzer,address,undefined)
    target_link_options(fuzz_${fuzzer} PRIVATE -fsanitize=fuzzer,address,undefined)
  endforeach()
endif()
