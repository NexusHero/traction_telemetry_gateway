# Security Policy

This repository is a **DevSecOps reference project**. It exists to demonstrate a
secure-by-default C++ delivery pipeline, not to be deployed. Please report issues
accordingly.

## Supported versions

Only the `main` branch is maintained. There are no release branches and no
long-term support window.

## Reporting a vulnerability

Do **not** open a public issue for a vulnerability.

Email the maintainer directly with:

- A description of the issue
- The affected component (parser, HTTP layer, build pipeline, ...)
- Steps to reproduce, or a proof of concept if available
- Whether you are happy to be credited

You will receive an acknowledgement within 3 business days, and an update at
least every 14 days until the issue is resolved. We follow a coordinated
disclosure process: a fix is prepared and released before details are made
public.

## Scope of a "vulnerability"

For this project, that means anything that lets an attacker over the network or
via crafted frames cause the parser or server to:

- read or write out of bounds (memory safety),
- panic / crash without a bounded, defined rejection path,
- bypass the payload/rate limits (resource exhaustion, FR 7 of IEC 62443-4-2),
- or otherwise break the trust boundary documented in `docs/threat-model.md`.

## What this repo does about security

| Concern | Mechanism |
| --- | --- |
| Formatting / lint drift | `pre-commit` hooks locally, `clang-format` gate in CI |
| Secrets in the repository | `gitleaks` gate in CI, over the full history |
| Memory safety (own code) | ASan + UBSan test runs, libFuzzer on the parser (cumulative corpus) |
| Data races | ThreadSanitizer over `tests/test_concurrency.cpp` |
| Static analysis | clang-tidy, cppcheck (regression gate vs. `.sast-baseline.txt`), GitHub CodeQL |
| Test adequacy | coverage reported per run and per release — reported, never gated |
| Supply chain (CVE) | Conan lockfile, SBOM (CycloneDX from the Conan graph), `conan audit` gate (CVSS >= 9.0) |
| Supply chain (licence) | `scripts/license_check.py`, permissive allowlist, default-deny |
| Container | distroless base, built from the scanned lockfile, `trivy` gate, image SBOM |
| Artefact integrity | `cosign` signature by digest, SBOM attestation, SLSA provenance |
| Auditability | per-release evidence bundle with the output of every gate |

## The static-analysis baseline

`clang-tidy` and `cppcheck` are a gate on **regressions**, not on absolute
cleanliness. `scripts/sast_gate.py` compares their output against
`.sast-baseline.txt` and fails the build on anything the baseline does not
account for.

This is step 2 of the standard rollout:

1. Run the tool without a gate; let it collect a baseline.
2. **Freeze the baseline. Treat only *new* findings as blocking.** ← where this
   project sits
3. Tighten further once the baseline is empty (`--error-exitcode=1` for
   cppcheck, `WarningsAsErrors` in `.clang-tidy`).

A gate that floods a team with pre-existing findings gets disabled within two
weeks; a baseline prevents that, and shrinking it is the easy direction —
lowering a count is always safe, raising one needs a reason in the pull request
that does it.

Two deliberate properties of the gate:

- **The baseline is not keyed on line numbers.** A line-keyed baseline
  invalidates itself on the next edit above a finding, which trains people to
  regenerate it blindly — and a blindly regenerated baseline accepts whatever is
  in the tree, gate included. Keying on `(file, check)` with a count survives
  edits while still catching a second instance of a known check.
- **A missing or unparseable report is a hard failure**, not a skip. A report
  that does not exist yields zero findings, which would otherwise sail through
  as a pass and report success for an analyser that never ran. For the same
  reason CI pins `cppcheck --template`: an unparseable report looks exactly like
  a clean one.

## Gate thresholds

| Stage | Gate | Threshold | Where |
| --- | --- | --- | --- |
| 1 | clang-format | any deviation | `ci.yml` |
| 2 | gitleaks | any finding, full history | `ci.yml` |
| 3 | clang-tidy + cppcheck | beyond `.sast-baseline.txt` | `ci.yml` |
| 4 | `conan audit` | CVSS >= 9.0 | `supply-chain.yml` |
| 4 | licence policy | not on the allowlist, or undeclared | `supply-chain.yml` |
| 5 | ctest, ASan/UBSan, TSan | any failure | `ci.yml` |
| 5 | coverage | *none — reported only* | `ci.yml` |
| 6 | libFuzzer | any crash reproducer | `fuzzing.yml` |
| 7 | trivy (image) | CRITICAL, fixed only | `supply-chain.yml` |

Thresholds are set where they are defensible rather than where they look
strictest. `--ignore-unfixed` on trivy is the clearest example: failing a build
on a CVE with no available fix gives a team no action to take, and a gate with no
available action is a gate that gets bypassed.

A release additionally refuses to proceed without a CVE scan. On a pull request
from a fork the token is unavailable and the scan is skipped with a warning,
because a contributor cannot fix that; cutting a version whose dependencies were
never checked is a different matter.
