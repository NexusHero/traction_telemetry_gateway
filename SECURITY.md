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
| Secrets in the repository | `gitleaks` gate in CI |
| Memory safety (own code) | ASan + UBSan test runs, libFuzzer on the parser |
| Static analysis | clang-tidy, cppcheck, GitHub CodeQL |
| Supply chain | Conan lockfile, SBOM (CycloneDX from the Conan graph), `conan audit` CVE gate (CVSS >= 9.0) |
| Container | distroless base, `trivy` image scan gate, `cosign` signing |

## Turning reporting into a gate

`clang-tidy` and `cppcheck` currently run as *reporting* stages (results are
uploaded as artifacts). The recommended rollout, and the one this project
models, is:

1. Run the tool without a gate; let it collect a baseline.
2. Freeze the baseline. Treat only *new* findings as blocking.
3. Tighten the gate once the baseline is clean (`--error-exitcode=1` for
   cppcheck, `-warnings-as-errors` for clang-tidy).

A gate that floods a team with pre-existing findings gets disabled within two
weeks; a baseline prevents that.
