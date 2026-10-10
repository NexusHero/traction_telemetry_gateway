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

# One sanitizer at a time, by design: ASan and TSan use incompatible runtimes
# and cannot be linked into the same binary. Modelling this as a single-valued
# option makes the invalid combination unrepresentable instead of a link error.
#   address = AddressSanitizer + UBSan (memory safety, the parser's main risk)
#   thread  = ThreadSanitizer (the store is shared across httplib's pool)
set(TTG_SANITIZER "off" CACHE STRING "Sanitizer to instrument with: off, address, thread")
set_property(CACHE TTG_SANITIZER PROPERTY STRINGS off address thread)

find_package(Threads REQUIRED)

set(TTG_WARNINGS -Wall -Wextra -Wpedantic -Wshadow -Wconversion)
# Off by default so a newer compiler on a developer's machine cannot break their
# build over a warning that did not exist when the code was written. CI turns it
# on, against pinned compilers, which is where a new warning should surface.
if(TTG_WARNINGS_AS_ERRORS)
    list(APPEND TTG_WARNINGS -Werror)
endif()

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

# ---------------------------------------------------------------------------
# Exploit mitigations for the shipped binary. The parser's job is to survive
# hostile input; these make the failure mode of a parser bug that slips through
# anyway a crash rather than code execution:
#   _FORTIFY_SOURCE=3        bounds-checked libc calls where the size is known
#   stack-protector-strong   stack canaries
#   stack-clash-protection   no jumping the guard page with a large frame
#   cf-protection / branch-protection   CET (x86-64) / PAC+BTI (AArch64)
#   PIE + full RELRO + BIND_NOW + non-exec stack   ASLR and a read-only GOT
# scripts/check_hardening.sh verifies the result on the built ELF, because a
# flag that a toolchain silently ignores is indistinguishable from one it
# applied.
#
# Linux only: the target is a Linux box and the -z linker options are GNU ld /
# lld syntax that Apple's linker rejects. Skipped for sanitizer, coverage and
# fuzzing builds, which exist to find bugs, not to ship: FORTIFY's checked libc
# calls overlap ASan's interceptors, and both distort coverage.
# ---------------------------------------------------------------------------
set(TTG_HARDEN_COMPILE "")
set(TTG_HARDEN_LINK "")
if(TTG_HARDENING AND CMAKE_SYSTEM_NAME STREQUAL "Linux" AND TTG_SANITIZER STREQUAL "off"
   AND NOT TTG_ENABLE_COVERAGE AND NOT TTG_ENABLE_FUZZING)
    # FORTIFY needs optimisation to see object sizes and warns without it, which
    # -Werror would turn into a failed Debug build. -U first: Ubuntu's GCC
    # predefines a level, and redefining it is itself a warning.
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

    # PIE through CMake rather than raw -fPIE/-pie, so static libraries are
    # compiled position-independent too and nothing links non-PIC objects into
    # a PIE.
    include(CheckPIESupported)
    check_pie_supported()
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()

# Every target gets both instrumentation sets; exactly one of them is ever
# non-empty. Hardening is kept apart because its compile and link halves differ,
# and it is empty whenever either instrumentation set is not.
set(TTG_INSTRUMENTATION ${TTG_SANITIZE_FLAGS} ${TTG_COVERAGE_FLAGS})

# ---------------------------------------------------------------------------
# Parser - the trust boundary. No third-party dependencies, so it can be built
# and fuzzed standalone with a bare Clang toolchain (no Conan).
# ---------------------------------------------------------------------------
add_library(ttg_parser STATIC src/parser.cpp)
target_include_directories(ttg_parser PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_options(ttg_parser PRIVATE ${TTG_WARNINGS} ${TTG_INSTRUMENTATION} ${TTG_HARDEN_COMPILE})
target_link_options(ttg_parser PUBLIC ${TTG_INSTRUMENTATION} ${TTG_HARDEN_LINK})

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
    target_compile_options(ttg_core PRIVATE ${TTG_WARNINGS} ${TTG_INSTRUMENTATION} ${TTG_HARDEN_COMPILE})
    target_link_options(ttg_core PUBLIC ${TTG_INSTRUMENTATION} ${TTG_HARDEN_LINK})
endif()

# ---------------------------------------------------------------------------
# REST server
# ---------------------------------------------------------------------------
# The HTTP layer is a library of its own so the tests can exercise it in
# process; the executable is just main() on top.
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
        tests/test_http_server.cpp
        tests/test_security_log.cpp)

    # Threads::Threads is needed for test_concurrency.cpp: on Linux std::thread
    # resolves at link time against pthread, and a build without it fails (or,
    # worse on older toolchains, aborts at run time).
    target_link_libraries(ttg_tests PRIVATE ttg_http httplib::httplib GTest::gtest_main Threads::Threads)
    target_compile_options(ttg_tests PRIVATE ${TTG_WARNINGS} ${TTG_INSTRUMENTATION} ${TTG_HARDEN_COMPILE})
    target_link_options(ttg_tests PRIVATE ${TTG_INSTRUMENTATION} ${TTG_HARDEN_LINK})

    # The checked-in fuzzing seeds and every crash reproducer ever added next to
    # them are replayed by tests/test_parser.cpp on every build - including the
    # sanitizer jobs - so a fixed fuzzer finding stays fixed.
    target_compile_definitions(ttg_tests PRIVATE
        TTG_CORPUS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/corpus")

    include(GoogleTest)
    # The concurrency tests spin up threads and hammer a mutex; under TSan they
    # are an order of magnitude slower than the rest of the suite, so the
    # default 5s discovery timeout is not enough.
    gtest_discover_tests(ttg_tests DISCOVERY_TIMEOUT 60 PROPERTIES TIMEOUT 300)

    # Real-time gate: allocation bounds of the parser. A separate executable
    # because it replaces the global operator new (see the file's header).
    add_executable(ttg_rt_tests tests/test_realtime.cpp)
    target_link_libraries(ttg_rt_tests PRIVATE ttg_parser GTest::gtest_main)
    target_compile_options(ttg_rt_tests PRIVATE ${TTG_WARNINGS} ${TTG_INSTRUMENTATION} ${TTG_HARDEN_COMPILE})
    target_link_options(ttg_rt_tests PRIVATE ${TTG_INSTRUMENTATION} ${TTG_HARDEN_LINK})
    gtest_discover_tests(ttg_rt_tests DISCOVERY_TIMEOUT 60)
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
    # Benchmarks measure the shipped configuration, so they get the hardening
    # flags too: a mitigation's cost is part of what the numbers should show.
    target_compile_options(ttg_benchmarks PRIVATE ${TTG_WARNINGS} ${TTG_HARDEN_COMPILE})
    target_link_options(ttg_benchmarks PRIVATE ${TTG_HARDEN_LINK})
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
