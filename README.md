# Traction Telemetry Gateway

A small, hardened **C++20 REST service** that ingests binary telemetry frames
from a (fictional) traction bus, validates them at a well-defined trust
boundary, and exposes the latest values as JSON.

It is a **DevSecOps reference project**: the interesting part is less the app
itself and more the pipeline that ships it — static analysis, sanitizers,
fuzzing, SBOM, dependency scanning, a distroless image and artifact signing.

```
[telemetry producer] --POST /v1/frames (binary)--> [TTG gateway] --> JSON API
```

## Why this shape

Every C++ service that speaks a protocol has one thing in common: **a parser that
reacts to input it did not choose.** That parser is the primary attack surface,
and everything in this repo is built around defending it:

- The wire format (`include/ttg/frame.hpp`) is deliberately length-prefixed, so
  it has the same pitfalls real protocols have: truncated lengths, oversized
  fields, integer edge cases.
- `ttg::parse_frame` is **total**: no input throws, reads out of bounds, or
  allocates an attacker-controlled amount of memory.
- The parser is unit-tested, stress-tested against arbitrary input, and fuzzed
  with libFuzzer.

## Build

Dependencies are managed with **Conan 2** (ConanCenter).

```sh
conan profile detect --force
conan install . --build=missing -of build -s build_type=Release
cmake -S . -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_TOOLCHAIN_FILE=build/conan_toolchain.cmake
cmake --build build --parallel
ctest --test-dir build --output-on-failure
./build/ttg_server            # listens on 0.0.0.0:8080
```

Environment variables: `TTG_HOST` (default `0.0.0.0`), `TTG_PORT` (default
`8080`), `TTG_MAX_CHANNELS` (default `4096`).

### Smoke test

```sh
python3 tools/gen_frame.py 1 > /tmp/frame.bin
curl --data-binary @/tmp/frame.bin http://127.0.0.1:8080/v1/frames
curl http://127.0.0.1:8080/v1/telemetry
```

### Sanitizers

```sh
cmake -S . -B build-asan -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_TOOLCHAIN_FILE=build/conan_toolchain.cmake \
  -DTTG_ENABLE_SANITIZERS=ON
cmake --build build-asan --parallel
ctest --test-dir build-asan --output-on-failure
```

### Fuzzing (Linux + Clang only)

The parser has no third-party dependencies, so the fuzzer builds without Conan:

```sh
cmake -S . -B build-fuzz -G Ninja \
  -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
  -DTTG_BUILD_SERVER=OFF -DTTG_BUILD_TESTS=OFF -DTTG_ENABLE_FUZZING=ON
cmake --build build-fuzz --target fuzz_frame_parser
./build-fuzz/fuzz_frame_parser tests/corpus/ -max_total_time=300
```

### Benchmarks (runtime + memory)

Google Benchmark with allocation tracking (global `operator new` counters):

```sh
conan install . --build=missing -of build -s build_type=Release -o build_benchmarks=True
cmake -S . -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_TOOLCHAIN_FILE=build/conan_toolchain.cmake \
  -DTTG_BUILD_BENCHMARKS=ON
cmake --build build --target ttg_benchmarks
./build/ttg_benchmarks --benchmark_min_time=0.05s
```

The `allocs` / `alloc_bytes` columns show how much the code under test
allocates **per iteration**. The interesting findings for this project:

- `parse_frame` allocates **exactly once** (the output channel vector) and
  nothing on the reject path.
- `TelemetryStore::ingest` is **allocation-free in steady state** (channels are
  updated in place).
- `crc16_ccitt` allocates nothing, as expected for a pure function.

That is the concrete, measurable version of "keine Allokation im heißen Pfad".

## HTTP API

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/v1/frames` | Ingest one binary frame. `202` on success, `400` with a status token otherwise. |
| `GET` | `/v1/telemetry` | Latest value per channel as JSON. |
| `GET` | `/v1/stats` | Counters (received, rejected, tracked channels). |
| `GET` | `/healthz` | Liveness. |
| `GET` | `/readyz` | Readiness. |

## Wire format

Documented in `include/ttg/frame.hpp`. Big-endian, CRC-16/CCITT-FALSE:

```
magic(2) version(1) msg_type(1) sequence(4) timestamp_ms(8) payload_len(2) payload crc16(2)
```

## Pipeline

| Workflow | Runs | Purpose |
| --- | --- | --- |
| `ci.yml` | push / PR | Build & test (Ubuntu + macOS), ASan/UBSan, clang-tidy + cppcheck, gitleaks |
| `supply-chain.yml` | push / PR / tag | SBOM (CycloneDX), grype CVE gate, distroless image build, trivy scan, cosign sign |
| `fuzzing.yml` | nightly | libFuzzer on the parser, 15 minutes |
| `benchmarks.yml` | weekly / manual | runtime + allocation benchmarks (Google Benchmark) |
| `codeql.yml` | push / PR | CodeQL analysis (C++) |

See `SECURITY.md` for the vulnerability policy and the "baseline" rollout for
static analysis, and `docs/threat-model.md` for the STRIDE model.
