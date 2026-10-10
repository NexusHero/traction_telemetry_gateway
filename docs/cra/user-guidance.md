# Information and instructions for the user

CRA Annex II lists what a manufacturer must give the user of a product with
digital elements. This is that information for the Traction Telemetry Gateway.
Sections are grouped by topic; each Annex II point is covered by one of them.

## Manufacturer and contact

- Manufacturer: Suhay Sevinc, maintainer of
  <https://github.com/NexusHero/traction_telemetry_gateway> (reference project).
- Single point of contact for vulnerabilities: private vulnerability reporting
  on the repository, see [`SECURITY.md`](../../SECURITY.md). The coordinated
  disclosure policy is in [`vulnerability-handling.md`](vulnerability-handling.md).

## Product and intended purpose

- Product: `ttg_server`, distributed as a signed container image
  (`ghcr.io/nexushero/traction_telemetry_gateway`) and as a release tarball.
- Intended purpose, environment and known risks: see
  [`risk-assessment.md`](risk-assessment.md).
- Essential security properties: authenticated ingest, a parser that rejects
  every malformed frame without crashing, bounded memory, exploit mitigations
  in the binary, a security event log.

## Secure deployment

Required for the product to meet its security properties:

1. **TLS in front of the gateway.** The process speaks plain HTTP. Put a
   TLS-terminating reverse proxy in front of it and bind the gateway to an
   interface only the proxy can reach (`TTG_HOST`). Use mutual TLS between
   producers and the proxy where the producers support it.
2. **Ingest token from a secret.** Generate at least 32 random characters
   (`openssl rand -hex 32`), mount them as a read-only file and point
   `TTG_INGEST_TOKEN_FILE` at it. Prefer the file over `TTG_INGEST_TOKEN`: an
   environment variable is visible in `docker inspect` and process listings.
   Rotate the token when a producer is decommissioned or suspected compromised.
3. **Rate limiting at the proxy.** Limit requests per client on
   `POST /v1/frames`; the gateway bounds its own resource use but does not
   throttle clients (accepted risk R4).
4. **Collect the security event log.** One JSON object per line on stderr:
   `auth_failure`, `frame_rejected`, `config`, `events_suppressed`. Alert on
   sustained `auth_failure`.
5. **Run the signed image as published.** Non-root, read-only root filesystem
   possible, no capabilities needed.

Security-relevant configuration and its defaults:

| Variable | Default | Secure setting |
| --- | --- | --- |
| `TTG_INGEST_TOKEN_FILE` / `TTG_INGEST_TOKEN` | none - the gateway refuses to start | a 32+ character secret, from a file |
| `TTG_ALLOW_UNAUTHENTICATED_INGEST` | unset | leave unset; `1` disables authentication and is logged |
| `TTG_SECURITY_LOG` | `on` | `on`; `off` is the opt-out required by Annex I (2)(l) |
| `TTG_HOST` | `0.0.0.0` | the private interface the proxy uses |

## Security updates

- Security fixes are released as patch versions, free of charge, and announced
  as GitHub Security Advisories on the repository. Watch the repository's
  releases and security advisories to be notified.
- Verify before deploying:

  ```sh
  sha256sum -c SHA256SUMS
  gh attestation verify ttg-<version>-linux-x86_64.tar.gz -R NexusHero/traction_telemetry_gateway
  cosign verify ghcr.io/nexushero/traction_telemetry_gateway:<version> \
    --certificate-identity-regexp '^https://github.com/NexusHero/traction_telemetry_gateway/' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
  ```

- Deploy images by digest, and let your update tooling (Renovate, Dependabot,
  or the fleet manager) propose new digests automatically, so that installing
  a security update is the default path rather than a manual one.

## Support period

Security updates for every release for 5 years from its release date, and for
the product at least until 2031-12-31 - stated in
[`SECURITY.md`](../../SECURITY.md). After the end of support no further fixes
are published; replace or isolate the gateway before that date.

## Software bill of materials

Every release carries a CycloneDX 1.5 SBOM (`sbom.cdx.json` in the evidence
bundle, also attested to the binary) that meets BSI TR-03183-2, and the image
carries its own SBOM attestation in the registry.

## Decommissioning and data removal

The gateway stores nothing persistently: stopping the process removes all
telemetry it held. Revoke the ingest token at the producers and the secret
store, and delete the container and its secret mount.
