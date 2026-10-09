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

# One sanitizer at a time, by design: ASan and TSan use incompatible runtimes
# and cannot be linked into the same binary. Modelling this as a single-valued
# option makes the invalid combination unrepresentable instead of a link error.
#   address = AddressSanitizer + UBSan (memory safety, the parser's main risk)
#   thread  = ThreadSanitizer (the store is shared across httplib's pool)
set(TTG_SANITIZER "off" CACHE STRING "Sanitizer to instrument with: off, address, thread")
set_property(CACHE TTG_SANITIZER PROPERTY STRINGS off address thread)

find_package(Threads REQUIRED)

set(TTG_WARNINGS -Wall -Wextra -Wpedantic -Wshadow -Wconversion)

set(TTG_SANITIZE_FLAGS "")
if(TTG_SANITIZER STREQUAL "address")
    # -fno-sanitize-recover makes the first UB finding fatal; without it a test
    # can report a diagnostic and still exit 0, which CI would call a pass.
    set(TTG_SANITIZE_FLAGS -fsanitize=address,undefined -fno-omit-frame-pointer
                           -fno-sanitize-recover=all)
elseif(TTG_SANITIZER STREQUAL "thread")
    set(TTG_SANITIZE_FLAGS -fsanitize=thread -fno-omit-frame-pointer)
elseif(NOT TTG_SANITIZER STREQUAL "off")
    message(FATAL_ERROR
        "TTG_SANITIZER must be one of: off, address, thread (got '${TTG_SANITIZER}')")
endif()

# Coverage instrumentation is orthogonal to the sanitizers but pointless to
# combine with them: the sanitizer runtimes distort the line counts and the
# builds exist for different questions. Refuse the combination rather than
# produce numbers nobody should trust.
set(TTG_COVERAGE_FLAGS "")
if(TTG_ENABLE_COVERAGE)
    if(NOT TTG_SANITIZER STREQUAL "off")
        message(FATAL_ERROR
            "TTG_ENABLE_COVERAGE and TTG_SANITIZER=${TTG_SANITIZER} are mutually "
            "exclusive - run them as separate builds.")
    endif()
    # -fprofile-update=atomic is not optional here: tests/test_concurrency.cpp
    # drives the same lines from several threads, and the default non-atomic
    # counter updates race, producing coverage data that is quietly wrong.
    set(TTG_COVERAGE_FLAGS --coverage -fprofile-update=atomic -g -O0)
endif()

# Every target gets both sets; exactly one of them is ever non-empty.
set(TTG_INSTRUMENTATION ${TTG_SANITIZE_FLAGS} ${TTG_COVERAGE_FLAGS})

# ---------------------------------------------------------------------------
# Parser - the trust boundary. No third-party dependencies, so it can be built
# and fuzzed standalone with a bare Clang toolchain (no Conan).
# ---------------------------------------------------------------------------
add_library(ttg_parser STATIC src/parser.cpp)
target_include_directories(ttg_parser PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_options(ttg_parser PRIVATE ${TTG_WARNINGS} ${TTG_INSTRUMENTATION})
target_link_options(ttg_parser PUBLIC ${TTG_INSTRUMENTATION})

# ---------------------------------------------------------------------------
# Core (store + JSON serialization). Needs nlohmann_json.
# ---------------------------------------------------------------------------
if(TTG_BUILD_SERVER OR TTG_BUILD_TESTS OR TTG_BUILD_BENCHMARKS)
    find_package(nlohmann_json CONFIG REQUIRED)

    add_library(ttg_core STATIC
        src/telemetry_store.cpp
        src/report.cpp)
    target_include_directories(ttg_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_link_libraries(ttg_core PUBLIC ttg_parser nlohmann_json::nlohmann_json)
    target_compile_options(ttg_core PRIVATE ${TTG_WARNINGS} ${TTG_INSTRUMENTATION})
    target_link_options(ttg_core PUBLIC ${TTG_INSTRUMENTATION})
endif()

# ---------------------------------------------------------------------------
# REST server
# ---------------------------------------------------------------------------
# The HTTP layer is a library of its own so the tests can exercise it in
# process; the executable is just main() on top.
if(TTG_BUILD_SERVER OR TTG_BUILD_TESTS)
    find_package(httplib CONFIG REQUIRED)

    add_library(ttg_http STATIC src/http_server.cpp)
    target_include_directories(ttg_http PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_link_libraries(ttg_http PUBLIC ttg_core PRIVATE httplib::httplib Threads::Threads)
    target_compile_options(ttg_http PRIVATE ${TTG_WARNINGS} ${TTG_INSTRUMENTATION})
    target_link_options(ttg_http PUBLIC ${TTG_INSTRUMENTATION})
endif()

if(TTG_BUILD_SERVER)
    add_executable(ttg_server src/main.cpp)

    target_link_libraries(ttg_server PRIVATE ttg_http Threads::Threads)
    target_compile_options(ttg_server PRIVATE ${TTG_WARNINGS} ${TTG_INSTRUMENTATION})
    target_link_options(ttg_server PRIVATE ${TTG_INSTRUMENTATION})
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
        tests/test_report.cpp
        tests/test_concurrency.cpp
        tests/test_http_server.cpp)

    # Threads::Threads is needed for test_concurrency.cpp: on Linux std::thread
    # resolves at link time against pthread, and a build without it fails (or,
    # worse on older toolchains, aborts at run time).
    target_link_libraries(ttg_tests PRIVATE ttg_http httplib::httplib GTest::gtest_main Threads::Threads)
    target_compile_options(ttg_tests PRIVATE ${TTG_WARNINGS} ${TTG_INSTRUMENTATION})
    target_link_options(ttg_tests PRIVATE ${TTG_INSTRUMENTATION})

    include(GoogleTest)
    # The concurrency tests spin up threads and hammer a mutex; under TSan they
    # are an order of magnitude slower than the rest of the suite, so the
    # default 5s discovery timeout is not enough.
    gtest_discover_tests(ttg_tests DISCOVERY_TIMEOUT 60 PROPERTIES TIMEOUT 300)
endif()

# ---------------------------------------------------------------------------
# Benchmarks (Google Benchmark): runtime and allocation metrics. Enabled with
# -DTTG_BUILD_BENCHMARKS=ON and -o build_benchmarks=True (Conan).
# ---------------------------------------------------------------------------
if(TTG_BUILD_BENCHMARKS)
    find_package(benchmark CONFIG REQUIRED)

    add_executable(ttg_benchmarks
        benchmarks/bench_parser.cpp
        benchmarks/bench_store.cpp
        benchmarks/memory_manager.cpp)

    target_include_directories(ttg_benchmarks PRIVATE benchmarks tests)
    target_link_libraries(ttg_benchmarks PRIVATE ttg_core benchmark::benchmark_main)
    target_compile_options(ttg_benchmarks PRIVATE ${TTG_WARNINGS})
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
