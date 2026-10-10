# Threat model — Traction Telemetry Gateway

One page, STRIDE over the trust boundaries. The model lives here so it can be
versioned and re-reviewed whenever the architecture changes (the step most teams
skip).

## System overview

```
[Train bus / telemetry producer]  --POST /v1/frames (binary)-->  [TTG gateway]
                                                                    |
                                                    [in-memory channel store]
                                                                    |
[Ops / dashboards]  <--GET /v1/telemetry, /v1/stats, /healthz----+
```

- The gateway is a single process. No persistence, no authentication in the
  current scope (see assumptions).
- The **trust boundary** is the `POST /v1/frames` body: arbitrary attacker-
  controlled bytes fed to `ttg::parse_frame`.

## STRIDE

| # | Threat | Violated property | Concrete vector | Mitigation |
| --- | --- | --- | --- | --- |
| S | Spoofing | Authenticity | A caller impersonates the telemetry bus and injects frames | Bearer token required on `POST /v1/frames`, checked before the parser in constant time; the server refuses to start without one (`docs/cra/user-guidance.md`). mTLS at the proxy as defence in depth |
| T | Tampering | Integrity | Frame is modified in transit, or an actor crafts a malformed frame | CRC-16 per frame; signed firmware/artifacts in the release pipeline |
| R | Repudiation | Non-repudiation | A rejection or ingest cannot be attributed | Security event log (JSON lines: auth failures and rejected frames with peer address, rate-limited); counters in `/v1/stats` |
| I | Information Disclosure | Confidentiality | Diagnostics leak via overly detailed error bodies; a browser on another origin embeds or caches responses | Errors return only a status token (`too_short`, `bad_crc`, ...), never data; `no-store`, deny-all CSP, CORP `same-origin`, `nosniff` on every response, checked by the ZAP scan |
| D | Denial of Service | Availability | Flood of frames exhausts memory or CPU | Body length cap, max channel count, bounded store (`max_channels`), parser is O(n) with no allocation on attacker-controlled sizes |
| E | Elevation of Privilege | Authorization | A diagnostic endpoint grants control over the store | Read-only vs. write endpoints are separated; no privileged endpoint exists yet |

## The parser: the one boundary that must be airtight

`ttg::parse_frame` is **total**: every input returns a `ParseResult`, never
throws, never reads out of bounds. The guarantees come from:

1. **Length before content** — every length field is checked against the actual
   buffer before any bytes are read.
2. **Upper bounds on everything** — `kMaxPayloadLen`, `kMaxChannels`.
3. **No allocation sized by attacker input** — channel vector is `reserve`d to a
   compile-time maximum.
4. **CRC checked before semantic parsing** — malformed data is rejected early.

Proof is not by review but by execution: unit tests, a `NeverThrowsOnArbitraryInput`
stress test, and a libFuzzer harness in `tests/fuzz_frame_parser.cpp`.

## Assumptions and out of scope

- One shared ingest credential for all producers, no per-producer identity or
  authorisation (IEC 62443-4-2 FR 2); read endpoints are open by design
  (`docs/cra/risk-assessment.md`, R8).
- No TLS termination in-process (expected to terminate at a proxy / service
  mesh).
- The channel store is volatile; there is no confidentiality requirement for
  telemetry values.

## Review triggers

Re-open this model when: the wire format changes, a new endpoint is added, the
service gains persistence or authentication, or the gateway is deployed outside
a trusted network segment.
