# Cybersecurity risk assessment

CRA Art. 13(2)-(3): the manufacturer assesses the cybersecurity risks of the
product, takes the result into account in planning, design, development,
production, delivery and maintenance, and documents it. This document is that
assessment for the Traction Telemetry Gateway. It builds on the STRIDE model in
[`docs/threat-model.md`](../threat-model.md) and adds what that model leaves
out: purpose, environment, rating, treatment and acceptance.

Re-assess when anything in the "review triggers" of the threat model changes,
and at least once per release that changes an interface.

## Intended purpose

A gateway that receives binary telemetry frames from producers on a traction
(rail vehicle) bus segment over HTTP, validates them, and serves the latest
value per channel as JSON to monitoring and diagnostic clients.

It is **not** part of a control loop and issues no commands: it observes. A
failure of the gateway loses visibility, not control of the vehicle.

## Reasonably foreseeable use and misuse

- Deployment on a network that is reachable from outside the vehicle segment
  (maintenance access, a misconfigured gateway router).
- Producers that are compromised or faulty and send malformed or hostile frames.
- Use as an input to decisions (maintenance planning, alarms), which makes the
  integrity of stored values matter even though nothing is controlled directly.

## Operating environment

- A Linux host or container platform on the vehicle or wayside, AArch64 or
  x86-64, running the signed distroless image as non-root.
- A TLS-terminating reverse proxy in front of the process (required, see
  [`user-guidance.md`](user-guidance.md)); the process itself speaks plain HTTP
  on a private interface.
- A log collector reading the security event log from stderr.

## Assets

| Asset | Property that matters |
| --- | --- |
| Stored telemetry values | integrity, availability |
| Ingest endpoint | authenticity of the producer |
| The process and its host | integrity (no code execution via input) |
| Ingest token | confidentiality |
| Release artefacts (binary, image, SBOM) | integrity, authenticity |

No personal data is processed. Telemetry values are technical measurements.

## Risks and treatment

Likelihood and impact on a three-step scale (low / medium / high).
"Residual" is the rating after the treatment that is in place today.

| # | Risk | Likelihood | Impact | Treatment in the product | Residual |
| --- | --- | --- | --- | --- | --- |
| R1 | Malformed frame causes memory corruption, code execution | medium | high | Total parser with bounds on every length field; ASan/UBSan, libFuzzer (nightly and per PR), corpus replay; exploit mitigations verified on the ELF | low |
| R2 | Unauthorised party injects or forges telemetry | medium | high | Bearer token required on ingest, secure by default (no token, no start), constant-time comparison; failed attempts counted and logged | low |
| R3 | Eavesdropping or tampering in transit, token theft | medium | medium | TLS at the mandatory reverse proxy; token from a secret file, never logged | low (with guidance followed) |
| R4 | Resource exhaustion by flooding | high | medium | Body size cap, bounded channel store, rate-limited security log; rate limiting at the proxy (guidance) | medium - accepted, see below |
| R5 | Vulnerable third-party component | medium | high | Locked dependency graph, CVE gates on dependencies and image, nightly rescan, Renovate/Dependabot | low |
| R6 | Compromised build or release pipeline | low | high | Actions pinned by SHA, least-privilege tokens, zizmor, signed artefacts with SLSA provenance, release only from a green pipeline | low |
| R7 | Attack goes unnoticed | medium | medium | Security event log (auth failures, rejected frames), counters at /v1/stats | low |
| R8 | Information disclosure through the read endpoints | low | low | Only technical telemetry is served; no personal or secret data; reads are open by design so monitoring keeps working when the ingest token rotates | low - accepted |

## Applicability of CRA Annex I, Part I

| Requirement | Applies | How |
| --- | --- | --- |
| (2)(a) no known exploitable vulnerabilities | yes | R5 |
| (2)(b) secure by default | yes | no start without a token; non-root, distroless |
| (2)(c) security updates | yes | release process, SECURITY.md, user guidance |
| (2)(d) protection from unauthorised access | yes | R2 |
| (2)(e) confidentiality | yes | R3 - by deployment: TLS at the proxy |
| (2)(f) integrity | yes | R2, R3, R6 |
| (2)(g) data minimisation | yes | latest value per channel only, in memory, bounded; no personal data |
| (2)(h) availability, DoS resilience | yes | R4 |
| (2)(i) impact on other devices and networks | yes | the gateway opens no outbound connections and only answers requests; it cannot be used to reach other systems |
| (2)(j) limited attack surface | yes | six endpoints, contract-tested; image without shell or package manager |
| (2)(k) exploitation mitigation | yes | R1 |
| (2)(l) security logging, with opt-out | yes | R7; `TTG_SECURITY_LOG=off` |
| (2)(m) secure removal of data | **no** | nothing is stored persistently; process exit removes all data |

## Accepted residual risks

- **R4, flooding.** The gateway bounds what a flood can consume, but rate
  limiting per client belongs in the proxy in front of it, where TLS already
  terminates. Accepted on the condition stated in the user guidance.
- **R8, open read endpoints.** Accepted: the data is not confidential, and
  monitoring must not depend on the ingest secret.

Accepted by: manufacturer (reference project), 2026-10-10.
