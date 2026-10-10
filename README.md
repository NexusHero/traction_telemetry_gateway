# Traction Telemetry Gateway

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/NexusHero/traction_telemetry_gateway/badge)](https://scorecard.dev/viewer/?uri=github.com/NexusHero/traction_telemetry_gateway)

A small, hardened **C++20 REST service** that ingests binary telemetry frames
from a (fictional) traction bus, validates them at a well-defined trust
boundary, and exposes the latest values as JSON.

It is a **DevSecOps reference project**: the interesting part is less the app
itself and more the pipeline that ships it — pre-commit hooks, secrets scanning,
static analysis with a regression baseline, sanitizers (ASan/UBSan and TSan),
coverage, fuzzing, SBOM, CVE and licence gates, a distroless image built from a
scanned lockfile, signing with provenance, and releases that carry their own
evidence.

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

### Local hooks

Stage 1 of the pipeline. The cheapest feedback is the kind that never reaches a
runner:

```sh
pip install pre-commit
pre-commit install                        # format + lint on every commit
pre-commit install --hook-type pre-push   # full-history secrets scan
pre-commit run --all-files                # one-off sweep
```

Hooks and CI share their configuration — `.clang-format`, `.clang-tidy` — so
they cannot disagree. CI still re-checks everything: `--no-verify` exists, and a
contributor who never ran `pre-commit install` has no hooks at all.

The `clang-tidy` hook needs a compilation database and skips itself with a hint
if there is none. To enable it, configure a build tree with
`-DCMAKE_EXPORT_COMPILE_COMMANDS=ON`.

### Sanitizers

ASan and TSan ship incompatible runtimes and cannot coexist in one binary, so
`TTG_SANITIZER` is single-valued rather than a set of switches — the invalid
combination is unrepresentable instead of a link error.

```sh
# address = AddressSanitizer + UBSan. The parser's main risk is memory safety.
cmake -S . -B build-asan -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_TOOLCHAIN_FILE=build/conan_toolchain.cmake \
  -DTTG_SANITIZER=address
cmake --build build-asan --parallel
ctest --test-dir build-asan --output-on-failure
```

```sh
# thread = ThreadSanitizer. TelemetryStore is shared across httplib's pool.
cmake -S . -B build-tsan -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_TOOLCHAIN_FILE=build/conan_toolchain.cmake \
  -DTTG_SANITIZER=thread
cmake --build build-tsan --parallel
TSAN_OPTIONS=halt_on_error=1 ctest --test-dir build-tsan --output-on-failure
```

TSan only reports what a test actually exercises, and the rest of the suite is
single-threaded — a TSan run over it would pass without touching a single lock.
`tests/test_concurrency.cpp` exists for this: writers on disjoint channel
ranges, readers racing them for the whole run, and assertions on the invariants
that must survive *any* interleaving (no lost update, no torn snapshot, the
channel cap holding under contention).

### Coverage

```sh
pip install gcovr
conan install . --build=missing -of build-cov -s build_type=Debug
cmake -S . -B build-cov -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_TOOLCHAIN_FILE=build-cov/conan_toolchain.cmake \
  -DTTG_ENABLE_COVERAGE=ON
cmake --build build-cov --parallel
ctest --test-dir build-cov --output-on-failure
gcovr --root . --filter 'src/' --filter 'include/' --print-summary
```

Coverage is **reported, never gated**. A threshold turns a diagnostic into a
target, and the cheapest way to hit a coverage target is to write tests that
execute code without asserting anything about it. The `--filter` flags matter
too: without them the header-only bulk of nlohmann_json and gtest dominates the
line count and the number stops describing this project.

Coverage and the sanitizers are mutually exclusive by design — CMake rejects the
combination rather than emitting line counts distorted by a sanitizer runtime.

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

### SBOM (local)

Conan has no SBOM command in core, so the pipeline uses `conan sbom:cyclonedx`
from the official [conan-extensions](https://github.com/conan-io/conan-extensions)
repo, pinned to a commit in `scripts/sbom.sh` (bump `EXTENSIONS_COMMIT` there
and in `sbom.ps1` deliberately). The wrapper installs that revision on first
run, or when the Conan home holds a different one; `cyclonedx-python-lib` comes
from `ci/requirements.txt`:

```sh
./scripts/sbom.sh                 # -> build/sbom.cdx.json (CycloneDX 1.4)
./scripts/sbom.sh --scan          # ... and run grype against it
```

```powershell
.\scripts\sbom.ps1               # same thing on Windows
```

The SBOM lists only what ships: `build_tests=False` drops gtest and
`--no-build-requires` drops cmake, leaving the two runtime dependencies with
their resolved recipe revisions:

```
pkg:conan/cpp-httplib@0.56.0?repository_url=https://center2.conan.io&rrev=2f12074...
pkg:conan/nlohmann_json@3.12.0?repository_url=https://center2.conan.io&rrev=2d634ab...
```

Two properties of this output are worth knowing.

**The CVE gate does not read this file.** The extension emits package URLs but
no CPEs, and file-based scanners match C/C++ packages on CPEs - `pkg:conan/...`
alone produces zero findings even for a package with known CVEs (measured
against `openssl/1.1.1a`: 0 matches by purl, 59 once a CPE is present). So this
SBOM is the component *inventory*, and the gate in `supply-chain.yml` is
`conan audit scan`, which resolves CVEs against the Conan references
themselves. `./scripts/sbom.sh --scan` runs grype for convenience, but treat a
clean result from it as weak evidence.

**The purls are not cache-stable.** When a recipe is downloaded in the same run,
the extension appends `repository_url=`; when it comes from a warm cache, it
does not. The same commit can therefore produce two slightly different purls.
This is upstream behaviour, left unmassaged rather than patched over here.

### Dependency pinning and updates

`conan.lock` is committed. Conan picks it up automatically, so every job, the
container image and the release resolve the same recipe revisions, and the
Dockerfile refuses to build without it. A dependency change is therefore always
a reviewable diff in `conanfile.py` and `conan.lock`, never a silent re-resolve
against whatever ConanCenter serves that day.

To change a dependency, edit `conanfile.py` and regenerate the lockfile:

```sh
conan lock create . --lockfile-out=conan.lock
```

Updates come from two bots, split so no dependency is proposed twice:

| What | Bot | Config |
| --- | --- | --- |
| Conan packages + `conan.lock` | [Renovate](https://docs.renovatebot.com/modules/manager/conan/) | `renovate.json` |
| GitHub Actions (SHA pins), Docker base image | Dependabot | `.github/dependabot.yml` |

Both wait 7 days before proposing a release. Renovate only runs once the
[Renovate GitHub App](https://github.com/apps/renovate) is installed on the
repository; until then `renovate.json` is inert.

### CVE scanning (local)

The CI gate uses `conan audit`, which is part of Conan core but needs a free
token from [conan.io/audit/register](https://conan.io/audit/register) - stored as
the repository secret `CONAN_AUDIT_TOKEN`. The token must be email-validated
before it works; `conan audit provider auth` stores it without checking, so an
invalid token shows up as a 403 on the first scan. Locally:

```sh
conan audit provider auth conancenter --token=<your_token>
conan audit scan . --context host --severity-level 9.0 -s build_type=Release
```

`--severity-level 9.0` is the default (critical only) and matches the trivy gate
on the image. `--context host` skips tool requires, which never reach the
runtime image.

### Licence policy (local)

The other half of stage 4. A CVE is a bug you can patch; a copyleft obligation
you shipped unknowingly is not fixable after the fact, so this is a gate rather
than a report:

```sh
python scripts/license_check.py                       # resolve and check
python scripts/license_check.py --graph graph.json    # check a saved graph
```

Default-deny against a permissive allowlist, and an **undeclared** licence counts
as a violation — "the recipe did not say" is exactly the case worth catching
early. The scope mirrors the SBOM (`build_tests=False`, host context only), so
the policy covers what ships rather than what was needed to build it: a
copyleft test framework never reaches a user, a copyleft runtime dependency
does.

Escape hatches are explicit and leave a trace in the diff:
`--extra-allow MPL-2.0` extends the policy, `--waive some-pkg/1.2.3` exempts one
package.

### DAST (local)

The running image is scanned with [ZAP](https://www.zaproxy.org/)'s API scan.
A JSON API has no links to crawl, so ZAP learns the endpoints from
`docs/openapi.yaml` - add new routes there in the same change that adds them to
the server, or they are never scanned.

```sh
docker build -f docker/Dockerfile -t ttg:ci .
docker network create dast
docker run -d --rm --name ttg --network dast ttg:ci
mkdir -p build/zap && cp docs/openapi.yaml .zap/rules.tsv build/zap/ && chmod -R a+rwX build/zap
docker run --rm --network dast -v "$PWD/build/zap:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:2.17.0 \
  zap-api-scan.py -t /zap/wrk/openapi.yaml -f openapi -O http://ttg:8080 -c rules.tsv -r zap-report.html
```

Mount a directory under your home on Colima / Docker Desktop for macOS; `/tmp`
is not shared with the VM. The gate fails on any WARN or FAIL that
`.zap/rules.tsv` does not explicitly accept, which is the DAST counterpart of
`.sast-baseline.txt`. The ZAP image is pinned because new ZAP releases add rules.

ZAP does not meaningfully test `POST /v1/frames`: its active rules attack named
parameters, and a binary body has none. The frame parser is covered by
libFuzzer instead; ZAP covers the HTTP layer around it.

### API contract fuzzing (local)

[Schemathesis](https://schemathesis.readthedocs.io/) generates requests from
`docs/openapi.yaml` and checks every response against it - no 5xx, only
documented status codes and content types, schema-valid bodies, `405` for
undeclared methods. Exceptions are in `schemathesis.toml`, each with a reason.
With the container from the DAST section running:

```sh
docker run --rm --network dast -v "$PWD:/w:ro" -w /tmp schemathesis/schemathesis:4.30.0 \
  --config-file /w/schemathesis.toml run /w/docs/openapi.yaml --url http://ttg:8080
```

### Static analysis baseline

`clang-tidy` and `cppcheck` run as a **gate on regressions**, not on absolute
cleanliness. `scripts/sast_gate.py` compares the analysers' output against
`.sast-baseline.txt`: findings recorded there are tolerated, anything new fails
the build.

```sh
# what CI runs
python scripts/sast_gate.py check clang-tidy.txt cppcheck.txt

# accept the current findings (review the diff - this is a policy change)
python scripts/sast_gate.py update clang-tidy.txt cppcheck.txt
```

The baseline is keyed on `(file, check)` with a count, deliberately **not** on
line numbers: a line-keyed baseline invalidates itself on the next edit above a
finding, which trains people to regenerate it blindly — and a blindly
regenerated baseline accepts whatever happens to be in the tree, gate included.
Counting instead means the baseline survives edits while a *second* instance of
an already-known check still fails.

The baseline currently starts empty, so the gate is strict. If CI surfaces
pre-existing findings, record them once with `update` and shrink the file from
there; lowering a count is always safe, raising one needs a reason in the pull
request that does it.

## HTTP API

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/v1/frames` | Ingest one binary frame. `202` on success, `400` with a status token otherwise. |
| `GET` | `/v1/telemetry` | Latest value per channel as JSON. |
| `GET` | `/v1/stats` | Counters (received, rejected, tracked channels). |
| `GET` | `/healthz` | Liveness. |
| `GET` | `/readyz` | Readiness. |

The machine-readable contract is `docs/openapi.yaml`. Every response carries
`Cache-Control: no-store`, a deny-all `Content-Security-Policy`,
`Cross-Origin-Resource-Policy: same-origin`, `X-Content-Type-Options: nosniff`
and `X-Frame-Options: DENY`, error responses included.

A wrong method on a known path is `405` with an `Allow` header (RFC 9110
15.5.6), including `TRACE` and `QUERY`; a method the server does not recognise
at all is `501`; unknown paths are `404`.

## Wire format

Documented in `include/ttg/frame.hpp`. Big-endian, CRC-16/CCITT-FALSE:

```
magic(2) version(1) msg_type(1) sequence(4) timestamp_ms(8) payload_len(2) payload crc16(2)
```

## Pipeline

### The eight stages, and where each one lives

| # | Stage | Where | Gate |
| --- | --- | --- | --- |
| 1 | Pre-commit | `.pre-commit-config.yaml`, `ci.yml` → `format` | clang-format deviation fails |
| 2 | Secrets scanning, pipeline audit | `ci.yml` → `secrets-scan` (gitleaks, full history), `workflow-audit` (zizmor) | any finding fails |
| 3 | SAST | `ci.yml` → `static-analysis`, `codeql.yml` | finding beyond `.sast-baseline.txt` fails |
| 4 | SCA / supply chain | `supply-chain.yml` → `sbom-and-scan` | CVSS ≥ 9.0 fails; licence allowlist, default-deny |
| 5 | Build & test | `ci.yml` → `build-and-test`, `cross-aarch64` (qemu), `sanitize` (ASan/UBSan + TSan), `coverage` | test or sanitizer failure fails; `-Werror`; allocation bounds of the parser (`ttg_rt_tests`); missing ELF hardening fails; coverage reported only |
| 6 | Dynamic / fuzzing / DAST | `ci.yml` → `fuzz-smoke` (60s per PR), `fuzzing.yml` (nightly, cumulative corpus), `supply-chain.yml` → `container` (ZAP API scan, Schemathesis) | any crash reproducer fails; any ZAP warning beyond `.zap/rules.tsv` fails; any Schemathesis failure fails |
| 7 | Image scan, SBOM & signing | `supply-chain.yml` → `container`, `release.yml`, `cve-rescan.yml` (nightly) | trivy or grype CRITICAL with a fix fails; produces SBOMs, signatures, provenance |
| 8 | Gate & release | all of the above + `release.yml` | green `ci.yml` on the tagged commit; binary from the same Dockerfile stage as the image; release carries the evidence |

### Workflows

| Workflow | Runs | Purpose |
| --- | --- | --- |
| `pipeline.yml` | push / PR / tag | **one run per commit**: calls `ci.yml` and `supply-chain.yml`, then a `report` job collects every artefact of the run into one evidence bundle (`pipeline-evidence`) and writes the **final pipeline report** - every gate's verdict, the key figures behind them, the compliance status, a hashed evidence inventory - to the run summary |
| `ci.yml` | called by `pipeline.yml` / manual | clang-format gate, build & test (Ubuntu + macOS, `-Werror`, **ELF hardening check**), **AArch64 cross build + tests under qemu**, ASan/UBSan, **TSan**, **coverage**, clang-tidy + cppcheck **baseline gate**, **60s fuzz smoke**, gitleaks, **zizmor workflow audit** |
| `supply-chain.yml` | called by `pipeline.yml` / manual | Conan lockfile, CycloneDX SBOM, `conan audit` CVE gate, **licence policy gate**, distroless image (no libssl) built **from the scanned lockfile**, trivy + **grype** scan, **ZAP API scan (DAST)**, **Schemathesis contract fuzzing**, image SBOM, cosign signature + SBOM attestation, SLSA provenance |
| `cve-rescan.yml` | nightly / manual | rebuilds main and pulls the latest release image, rescans both with trivy + grype against today's advisories; a finding fails the run and opens/updates a `security` issue |
| `fuzzing.yml` | nightly | libFuzzer on the parser; corpus **persists and is minimised** across runs; a reproducer fails the job |
| `release.yml` | tag `v*` / manual dry run | requires a green `pipeline.yml` run on the commit; release binary **from the Dockerfile build stage** (same as the image), tests with that toolchain, **evidence bundle**, checksums, provenance + SBOM attestation, GitHub Release |
| `benchmarks.yml` | weekly / manual | runtime + allocation benchmarks (Google Benchmark) |
| `codeql.yml` | push / PR / weekly | CodeQL analysis (C++) |
| `scorecard.yml` | push to main / weekly | OpenSSF Scorecard: published score (badge), findings uploaded to code scanning as SARIF |

Real-time and target-platform concerns - what CI can and cannot say about
latency, and what would need hardware - are in
[`docs/realtime.md`](docs/realtime.md).

### Hardening the pipeline itself

The workflows hold the registry token and the signing identity, so they get the
same treatment as source code:

- **Every action is pinned by commit SHA**, with the release in a trailing
  comment (`@3d3c42e… # v7.0.1`). A tag can be moved by whoever controls the
  action's repository; a SHA cannot. Dependabot updates the pins.
- **Downloaded tools are pinned by version and SHA-256** (trivy, grype), Python
  tooling by hash (`ci/requirements.txt`, installed with `--require-hashes` in
  CI and the image build), and container images by digest - ZAP, Schemathesis
  and both Dockerfile base images.
- **Least privilege per job.** Workflows default to `contents: read`; write
  scopes sit on the single job that needs them.
- **No persisted checkout credentials** (`persist-credentials: false`), no
  `${{ }}` expansion inside `run:` scripts (values go through `env:`), and no
  dependency cache on paths that produce signed artefacts.
- **Dependabot cooldown of 7 days**, so a freshly hijacked release has time to
  be noticed and yanked before it is proposed here.

`ci.yml` → `workflow-audit` runs [zizmor](https://docs.zizmor.sh/) over all of
this and fails on any finding. Locally:

```sh
pipx run zizmor==1.30.1 .
```

### Release and evidence

Tagging `v*` runs `release.yml`, which re-runs the gates against the exact tree
being shipped and publishes two assets plus checksums:

- `ttg-<version>-linux-x86_64.tar.gz` — the binary
- `ttg-<version>-evidence.tar.gz` — SBOM, `conan.lock`, CVE scan, licence
  verdict, analyser output, the SAST gate's verdict, coverage, and a
  `MANIFEST.md` explaining what each file records

Both carry a SLSA provenance attestation; the binary additionally carries an
SBOM attestation. The container image is signed and attested separately, **by
digest** rather than by tag — a tag is mutable, so signing `latest` says nothing
about which bytes a consumer will actually pull.

```sh
sha256sum -c SHA256SUMS
gh attestation verify ttg-<version>-linux-x86_64.tar.gz -R <owner>/<repo>
cosign verify ghcr.io/<owner>/<repo>@sha256:<digest> \
  --certificate-identity-regexp '^https://github.com/<owner>/<repo>/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The point of the bundle: an Actions artefact expires after 90 days and is bound
to a workflow run. A release asset with a provenance attestation is bound to a
version, and stays verifiable after everyone who ran the pipeline has forgotten
it existed.

`release.yml` can also be dispatched manually, which exercises the whole
evidence path and uploads the result as a workflow artefact without creating a
Release or consuming a version number.

A release is refused if the tag and the version in `conanfile.py` disagree: a
release labelled `v0.2.0` whose SBOM says `0.1.0` is worse than no SBOM, because
the evidence contradicts the artefact it describes.

### Compliance report (CRA, BSI TR-03183-2)

`scripts/compliance_report.py` turns a run's evidence into a report against
the EU Cyber Resilience Act (Annex I Parts I and II, Art. 13(8), Art. 14) and
the SBOM fields of BSI TR-03183-2. The mapping from requirement to check lives
in [`compliance/controls.toml`](compliance/controls.toml), reviewed like any
other gate configuration.

- **Every change** (`pipeline.yml`): evaluated against the evidence of the
  whole run - tests on every platform, sanitizers, SAST, hardening, SBOM, CVE
  and image scans, DAST - and summarised in the final pipeline report, so a
  pull request that breaks a control shows it before merge.
- **Every release** (`release.yml`): the report is part of the evidence bundle
  and covered by its provenance attestation; the summary goes into the release
  notes.

Each control's status is derived from its checks, never typed in, and every
piece of evidence is labelled by kind - *execution* (this run produced it),
*configuration* (a gate enforces it), *document* (a reviewed document states
it) - and hashed in an inventory. Gaps are reported, not hidden: the report is
designed to show an assessor what is shown and what is not.

```sh
# against a downloaded evidence bundle, or a local evidence/ directory
python scripts/compliance_report.py --evidence evidence \
  --out-md compliance-report.md --out-json compliance-report.json
```

It supports the technical documentation of a conformity assessment; it is not a
certification or a declaration of conformity.

See `SECURITY.md` for the vulnerability policy and the static-analysis baseline
workflow, and `docs/threat-model.md` for the STRIDE model.
