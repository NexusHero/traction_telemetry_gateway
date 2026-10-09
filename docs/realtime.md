# Real-time and target platform

What this pipeline checks about the gateway's behaviour on its target, what
it cannot check, and what would be needed to close the gap. The aim is an
honest boundary, not a claim of real-time certification.

## What CI enforces today

| Property | Where | How |
| --- | --- | --- |
| Builds and passes its tests on the target ISA (AArch64) | `ci.yml` → `cross-aarch64` | GCC 13 cross compiler, Conan host profile `ci/conan/linux-armv8-gcc13`, full test suite under `qemu-aarch64` |
| Parser allocation is bounded and input-independent | `tests/test_realtime.cpp` (`ttg_rt_tests`), every build incl. sanitizers and AArch64 | replaced global `operator new` counts allocations around `parse_frame`: header rejects allocate nothing, any frame at most one allocation of at most `kMaxChannels` entries |
| Parser is total over arbitrary input | `fuzzing.yml` (nightly), `ci.yml` → `fuzz-smoke` (60s per PR), corpus replay in `ttg_tests` | libFuzzer + ASan/UBSan; every reproducer committed to `tests/corpus` is replayed on every build |
| No data races in the shared store | `ci.yml` → `sanitize` (TSan) | `tests/test_concurrency.cpp` drives the store from several threads |
| Shipped binary carries exploit mitigations | `scripts/check_hardening.sh` in CI, the Dockerfile and the release | PIE, full RELRO, NX stack, canaries; read from the ELF, x86-64 and AArch64 |

## What CI deliberately does not claim

**Latency and jitter.** GitHub-hosted runners are shared VMs: other tenants,
frequency scaling, no CPU isolation. A p99 measured there tells you about the
neighbours, not the code. `benchmarks.yml` therefore reports, it does not gate.
qemu is worse still - it emulates the ISA, not the timing.

**WCET.** Worst-case execution time needs either static analysis of the
binary for the exact target CPU (aiT and similar) or measurement-based
evidence on the target under controlled load. Neither is meaningful in a
container.

**The HTTP layer is not a real-time path.** cpp-httplib uses a thread pool,
`std::string`, and allocates per request. That is acceptable for a
telemetry *gateway* - it sits beside the control loop, not in it - and it is
why the allocation gate covers the parser (the code that would move into a
real-time context) and not the server.

## Closing the gap: what the next steps would be

1. **A self-hosted runner on target hardware** (the AArch64 board, PREEMPT_RT
   kernel, `isolcpus` + `nohz_full` for the measured core, governor fixed to
   `performance`). Registered with a label and used only by a
   `latency` job that runs on `main` and on release tags, never on untrusted PR
   code - a self-hosted runner executing fork PRs is a remote code execution
   service.
2. **Latency gate on that runner**: run the parser benchmark and `cyclictest`
   under `stress-ng` load, record min/p99/p99.9/max, and fail on a regression
   against a stored baseline with a tolerance, not against an absolute number.
   Max matters more than mean in a real-time system.
3. **Zero allocations on the hot path**: replace `Frame::channels`
   (`std::vector`) with a fixed-capacity container sized by `kMaxChannels`,
   then tighten `kMaxAllocs` in `tests/test_realtime.cpp` to 0. The test is
   already the gate that would keep it there.
4. **Coding standard**: MISRA C++:2023 / AUTOSAR C++14 checking needs a
   qualified checker (the open-source tools here cover a subset at best). In a
   rail context the tool also needs a qualification argument (EN 50716 /
   EN 50128 tool classes T1-T3), which is a document, not a CI step.
5. **Hardware-in-the-loop**: replay recorded bus traffic into the gateway on
   the target board and compare outputs - the integration-level counterpart
   of the corpus replay above.

## Standards this maps to

Indicative only - a mapping, not a compliance statement.

| Concern | Rail standard | Here |
| --- | --- | --- |
| Software lifecycle, verification evidence | EN 50716 (successor of EN 50128) | evidence bundle per release (`release.yml`), traceable to commit and workflow run |
| Cybersecurity of rail systems | CLC/TS 50701, IEC 62443-4-1 (secure development) | threat model (`docs/threat-model.md`), SAST/DAST/fuzzing gates, SBOM, signed artefacts, vulnerability handling (`SECURITY.md`, nightly rescan) |
| Component security requirements | IEC 62443-4-2 | hardening of the binary and image, least privilege (non-root, distroless) |
