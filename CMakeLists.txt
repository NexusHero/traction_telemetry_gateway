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
option(TTG_BUILD_BENCHMARKS "Build the Google Benchmark suite" OFF)
option(TTG_ENABLE_FUZZING "Build the libFuzzer harness (Clang + libFuzzer only)" OFF)
option(TTG_ENABLE_COVERAGE "Instrument for line/branch coverage (gcov/llvm-cov)" OFF)
option(TTG_HARDENING "Compile and link with exploit mitigations (Linux only)" ON)
option(TTG_WARNINGS_AS_ERRORS "Turn compiler warnings into errors (CI sets this)" OFF)

set(TTG_SANITIZER "off" CACHE STRING "Sanitizer to instrument with: off, address, thread")
set_property(CACHE TTG_SANITIZER PROPERTY STRINGS off address thread)

find_package(Threads REQUIRED)

set(TTG_WARNINGS -Wall -Wextra -Wpedantic -Wshadow -Wconversion)
if(TTG_WARNINGS_AS_ERRORS)
    list(APPEND TTG_WARNINGS -Werror)
endif()

set(TTG_SANITIZE_FLAGS "")
if(TTG_SANITIZER STREQUAL "address")
    set(TTG_SANITIZE_FLAGS -fsanitize=address,undefined -fno-omit-frame-pointer
                           -fno-sanitize-recover=all)
elseif(TTG_SANITIZER STREQUAL "thread")
    set(TTG_SANITIZE_FLAGS -fsanitize=thread -fno-omit-frame-pointer)
elseif(NOT TTG_SANITIZER STREQUAL "off")
    message(FATAL_ERROR
        "TTG_SANITIZER must be one of: off, address, thread (got '${TTG_SANITIZER}')")
endif()

set(TTG_COVERAGE_FLAGS "")
if(TTG_ENABLE_COVERAGE)
    if(NOT TTG_SANITIZER STREQUAL "off")
        message(FATAL_ERROR
            "TTG_ENABLE_COVERAGE and TTG_SANITIZER=${TTG_SANITIZER} are mutually "
            "exclusive - run them as separate builds.")
    endif()
    set(TTG_COVERAGE_FLAGS --coverage -fprofile-update=atomic -g -O0)
endif()

set(TTG_HARDEN_COMPILE "")
set(TTG_HARDEN_LINK "")
if(TTG_HARDENING AND CMAKE_SYSTEM_NAME STREQUAL "Linux" AND TTG_SANITIZER STREQUAL "off"
   AND NOT TTG_ENABLE_COVERAGE AND NOT TTG_ENABLE_FUZZING)
    set(TTG_HARDEN_COMPILE
        "$<$<NOT:$<CONFIG:Debug>>:-U_FORTIFY_SOURCE;-D_FORTIFY_SOURCE=3>"
        -fstack-protector-strong
        -fstack-clash-protection)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|amd64)$")
        list(APPEND TTG_HARDEN_COMPILE -fcf-protection=full)
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64|armv8)$")
        list(APPEND TTG_HARDEN_COMPILE -mbranch-protection=standard)
    endif()
    set(TTG_HARDEN_LINK -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack)

    include(CheckPIESupported)
    check_pie_supported()
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()

set(TTG_INSTRUMENTATION ${TTG_SANITIZE_FLAGS} ${TTG_COVERAGE_FLAGS})

add_library(ttg_parser STATIC src/parser.cpp)
target_include_directories(ttg_parser PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_options(ttg_parser PRIVATE ${TTG_WARNINGS} ${TTG_INSTRUMENTATION} ${TTG_HARDEN_COMPILE})
target_link_options(ttg_parser PUBLIC ${TTG_INSTRUMENTATION} ${TTG_HARDEN_LINK})

if(TTG_BUILD_SERVER OR TTG_BUILD_TESTS OR TTG_BUILD_BENCHMARKS)
    find_package(nlohmann_json CONFIG REQUIRED)

    add_library(ttg_core STATIC
        src/telemetry_store.cpp
        src/report.cpp)
    target_include_directories(ttg_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_link_libraries(ttg_core PUBLIC ttg_parser nlohmann_json::nlohmann_json)
    target_compile_options(ttg_core PRIVATE ${TTG_WARNINGS} ${TTG_INSTRUMENTATION} ${TTG_HARDEN_COMPILE})
    target_link_options(ttg_core PUBLIC ${TTG_INSTRUMENTATION} ${TTG_HARDEN_LINK})
endif()

if(TTG_BUILD_SERVER OR TTG_BUILD_TESTS)
    find_package(httplib CONFIG REQUIRED)

    add_library(ttg_http STATIC src/http_server.cpp src/security_log.cpp)
    target_include_directories(ttg_http PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_link_libraries(ttg_http PUBLIC ttg_core PRIVATE httplib::httplib Threads::Threads)
    target_compile_options(ttg_http PRIVATE ${TTG_WARNINGS} ${TTG_INSTRUMENTATION} ${TTG_HARDEN_COMPILE})
    target_link_options(ttg_http PUBLIC ${TTG_INSTRUMENTATION} ${TTG_HARDEN_LINK})
endif()

if(TTG_BUILD_SERVER)
    add_executable(ttg_server src/main.cpp)

    target_link_libraries(ttg_server PRIVATE ttg_http Threads::Threads)
    target_compile_options(ttg_server PRIVATE ${TTG_WARNINGS} ${TTG_INSTRUMENTATION} ${TTG_HARDEN_COMPILE})
    target_link_options(ttg_server PRIVATE ${TTG_INSTRUMENTATION} ${TTG_HARDEN_LINK})
endif()

if(TTG_BUILD_TESTS)
    enable_testing()
    find_package(GTest CONFIG REQUIRED)

    add_executable(ttg_tests
        tests/test_parser.cpp
        tests/test_store.cpp
        tests/test_report.cpp
        tests/test_concurrency.cpp
        tests/test_http_server.cpp
        tests/test_security_log.cpp)

    target_link_libraries(ttg_tests PRIVATE ttg_http httplib::httplib GTest::gtest_main Threads::Threads)
    target_compile_options(ttg_tests PRIVATE ${TTG_WARNINGS} ${TTG_INSTRUMENTATION} ${TTG_HARDEN_COMPILE})
    target_link_options(ttg_tests PRIVATE ${TTG_INSTRUMENTATION} ${TTG_HARDEN_LINK})

    target_compile_definitions(ttg_tests PRIVATE
        TTG_CORPUS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/corpus")

    include(GoogleTest)
    gtest_discover_tests(ttg_tests DISCOVERY_TIMEOUT 60 PROPERTIES TIMEOUT 300)

    add_executable(ttg_rt_tests tests/test_realtime.cpp)
    target_link_libraries(ttg_rt_tests PRIVATE ttg_parser GTest::gtest_main)
    target_compile_options(ttg_rt_tests PRIVATE ${TTG_WARNINGS} ${TTG_INSTRUMENTATION} ${TTG_HARDEN_COMPILE})
    target_link_options(ttg_rt_tests PRIVATE ${TTG_INSTRUMENTATION} ${TTG_HARDEN_LINK})
    gtest_discover_tests(ttg_rt_tests DISCOVERY_TIMEOUT 60)
endif()

if(TTG_BUILD_BENCHMARKS)
    find_package(benchmark CONFIG REQUIRED)

    add_executable(ttg_benchmarks
        benchmarks/bench_parser.cpp
        benchmarks/bench_store.cpp
        benchmarks/memory_manager.cpp)

    target_include_directories(ttg_benchmarks PRIVATE benchmarks tests)
    target_link_libraries(ttg_benchmarks PRIVATE ttg_core benchmark::benchmark_main)
    target_compile_options(ttg_benchmarks PRIVATE ${TTG_WARNINGS} ${TTG_HARDEN_COMPILE})
    target_link_options(ttg_benchmarks PRIVATE ${TTG_HARDEN_LINK})
endif()

if(TTG_ENABLE_FUZZING)
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
