cmake_minimum_required(VERSION 3.20)

project(traction_telemetry_gateway
    VERSION 0.1.0
    DESCRIPTION "Hardened C++ REST gateway for traction telemetry frames"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

option(TTG_BUILD_SERVER "Build the REST server and core library" ON)
option(TTG_BUILD_TESTS "Build unit tests" ON)
option(TTG_ENABLE_FUZZING "Build the libFuzzer harness (Clang + libFuzzer only)" OFF)
option(TTG_ENABLE_SANITIZERS "Instrument builds with AddressSanitizer and UBSan" OFF)

find_package(Threads REQUIRED)

set(TTG_WARNINGS -Wall -Wextra -Wpedantic -Wshadow -Wconversion)
set(TTG_SANITIZE_FLAGS "")
if(TTG_ENABLE_SANITIZERS)
    set(TTG_SANITIZE_FLAGS -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)
endif()

# ---------------------------------------------------------------------------
# Parser - the trust boundary. No third-party dependencies, so it can be built
# and fuzzed standalone with a bare Clang toolchain (no Conan).
# ---------------------------------------------------------------------------
add_library(ttg_parser STATIC src/parser.cpp)
target_include_directories(ttg_parser PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_options(ttg_parser PRIVATE ${TTG_WARNINGS} ${TTG_SANITIZE_FLAGS})
target_link_options(ttg_parser PUBLIC ${TTG_SANITIZE_FLAGS})

# ---------------------------------------------------------------------------
# Core (store + JSON serialization). Needs nlohmann_json.
# ---------------------------------------------------------------------------
if(TTG_BUILD_SERVER OR TTG_BUILD_TESTS)
    find_package(nlohmann_json CONFIG REQUIRED)

    add_library(ttg_core STATIC
        src/telemetry_store.cpp
        src/report.cpp)
    target_include_directories(ttg_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_link_libraries(ttg_core PUBLIC ttg_parser nlohmann_json::nlohmann_json)
    target_compile_options(ttg_core PRIVATE ${TTG_WARNINGS} ${TTG_SANITIZE_FLAGS})
    target_link_options(ttg_core PUBLIC ${TTG_SANITIZE_FLAGS})
endif()

# ---------------------------------------------------------------------------
# REST server
# ---------------------------------------------------------------------------
if(TTG_BUILD_SERVER)
    find_package(httplib CONFIG REQUIRED)

    add_executable(ttg_server
        src/main.cpp
        src/http_server.cpp)

    target_link_libraries(ttg_server PRIVATE ttg_core httplib::httplib Threads::Threads)
    target_compile_options(ttg_server PRIVATE ${TTG_WARNINGS} ${TTG_SANITIZE_FLAGS})
    target_link_options(ttg_server PRIVATE ${TTG_SANITIZE_FLAGS})
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(TTG_BUILD_TESTS)
    enable_testing()
    find_package(GTest CONFIG REQUIRED)

    add_executable(ttg_tests
        tests/test_parser.cpp
        tests/test_store.cpp
        tests/test_report.cpp)

    target_link_libraries(ttg_tests PRIVATE ttg_core GTest::gtest_main)
    target_compile_options(ttg_tests PRIVATE ${TTG_WARNINGS} ${TTG_SANITIZE_FLAGS})

    include(GoogleTest)
    gtest_discover_tests(ttg_tests)
endif()

# ---------------------------------------------------------------------------
# Fuzzing (clang + libFuzzer). Apple Clang ships no libFuzzer, so this is
# intended for the Linux CI runner.
# ---------------------------------------------------------------------------
if(TTG_ENABLE_FUZZING)
    # libFuzzer is a Clang feature. AppleClang (macOS) does not ship it, so we
    # require exactly "Clang", which the Linux CI runner provides.
    if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        message(WARNING "TTG_ENABLE_FUZZING requested but the compiler is not Clang; skipping.")
    else()
        add_executable(fuzz_frame_parser tests/fuzz_frame_parser.cpp)
        target_link_libraries(fuzz_frame_parser PRIVATE ttg_parser)
        target_compile_options(fuzz_frame_parser PRIVATE
            -g -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
        target_link_options(fuzz_frame_parser PRIVATE
            -fsanitize=fuzzer,address,undefined)
    endif()
endif()
