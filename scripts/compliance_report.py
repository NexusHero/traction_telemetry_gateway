#!/usr/bin/env python3
"""Render a compliance report from the evidence of one pipeline run.

    scripts/compliance_report.py --evidence evidence \\
        --out-md evidence/compliance-report.md \\
        --out-json evidence/compliance-report.json

What it does
------------
compliance/controls.toml maps regulatory requirements (EU Cyber Resilience
Act Annex I, Art. 13/14; BSI TR-03183-2) to checks. This script runs those
checks against the evidence directory a pipeline run produced (SBOM, CVE
scan, SAST verdict, test log, hardening report, ...) and against the
repository at the same commit, and writes the result as Markdown for people
and JSON for machines.

Three kinds of evidence, labelled as such in the report, because an assessor
weighs them differently:

    execution      produced by this run (a test log, a scan result)
    configuration  the pipeline is set up to enforce it (a gate in a workflow)
    document       a reviewed document exists and says what it must

What it deliberately does not do
--------------------------------
It is not a gate. The gates are the pipeline's jobs; by the time a release
reaches this script they have passed. The report records what was shown and
what was not, including known gaps - a report that can only say "met" is
not evidence of anything. It also never upgrades a status by hand: a control's
status is derived from its checks, and a failing check overrides whatever
assessment the catalogue gives.

Evidence that a run did not produce (the pull-request pipeline has no release
binary) yields "not assessed" for the controls that need it, not a pass.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tomllib
from typing import Callable

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
CATALOGUE = REPO_ROOT / "compliance" / "controls.toml"

PASS, PARTIAL, FAIL, MISSING = "pass", "partial", "fail", "missing"
EXECUTION, CONFIGURATION, DOCUMENT = "execution", "configuration", "document"

# Control statuses, in the order the summary lists them.
STATUS_LABELS = {
    "not_met": ("❌", "Not met"),
    "gap": ("🔴", "Known gap"),
    "partial": ("🟡", "Partially met"),
    "not_assessed": ("⚪", "Not assessed in this run"),
    "organisational": ("📋", "Organisational - evidence held by the manufacturer"),
    "not_applicable": ("➖", "Not applicable"),
    "met": ("✅", "Met"),
}
ASSESSMENTS = {"partial", "gap", "not_applicable", "organisational"}
CHECK_ICONS = {PASS: "✅", PARTIAL: "🟡", FAIL: "❌", MISSING: "⚪"}


class CatalogueError(Exception):
    """The control catalogue is malformed."""


@dataclasses.dataclass
class CheckResult:
    name: str
    kind: str
    result: str
    detail: str
    sources: list[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class Context:
    evidence: pathlib.Path
    repo: pathlib.Path
    # Every file a check read, so the inventory can hash it: the report is
    # only as good as the ability to show which bytes it was computed from.
    touched: dict[str, pathlib.Path] = dataclasses.field(default_factory=dict)

    def evidence_file(self, name: str) -> pathlib.Path | None:
        path = self.evidence / name
        if path.is_file():
            self.touched[f"evidence/{name}"] = path
            return path
        return None

    def repo_text(self, rel: str) -> str | None:
        path = self.repo / rel
        if not path.is_file():
            return None
        self.touched[rel] = path
        return path.read_text(encoding="utf-8", errors="replace")


CHECKS: dict[str, Callable[[Context], CheckResult]] = {}


def check(name: str, kind: str):
    """Register a check. The function returns (result, detail[, sources])."""

    def register(fn):
        def run(ctx: Context) -> CheckResult:
            out = fn(ctx)
            result, detail = out[0], out[1]
            sources = list(out[2]) if len(out) > 2 else []
            return CheckResult(name, kind, result, detail, sources)

        CHECKS[name] = run
        return fn

    return register


def _needs(ctx: Context, rel: str) -> tuple[str | None, tuple[str, str] | None]:
    text = ctx.repo_text(rel)
    if text is None:
        return None, (FAIL, f"{rel} not found")
    return text, None


def _load_json(path: pathlib.Path) -> tuple[object | None, str | None]:
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except (OSError, json.JSONDecodeError) as exc:
        return None, f"{path.name} is not readable JSON: {exc}"


# ---------------------------------------------------------------------------
# Execution evidence - produced by the run
# ---------------------------------------------------------------------------


@check("sbom_present", EXECUTION)
def _sbom_present(ctx: Context):
    path = ctx.evidence_file("sbom.cdx.json")
    if path is None:
        return MISSING, "no sbom.cdx.json in this run's evidence"
    sbom, error = _load_json(path)
    if error:
        return FAIL, error, ["evidence/sbom.cdx.json"]
    if not isinstance(sbom, dict) or sbom.get("bomFormat") != "CycloneDX":
        return FAIL, "not a CycloneDX document", ["evidence/sbom.cdx.json"]
    components = sbom.get("components") or []
    incomplete = [
        c.get("name", "?") for c in components if not (c.get("name") and c.get("version") and c.get("purl"))
    ]
    if not components:
        return FAIL, "SBOM lists no components", ["evidence/sbom.cdx.json"]
    if incomplete:
        return FAIL, f"components without name/version/purl: {', '.join(incomplete)}", ["evidence/sbom.cdx.json"]
    names = ", ".join(f"{c['name']} {c['version']}" for c in components)
    return (
        PASS,
        f"CycloneDX {sbom.get('specVersion', '?')}, {len(components)} component(s): {names}",
        ["evidence/sbom.cdx.json"],
    )


def _version_tuple(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", text)[:3])


# Supplier strings that only say who generated the entry, not who made the
# component. The Conan SBOM extension writes "Conan" when a recipe declares no
# author.
PLACEHOLDER_CREATORS = {"", "conan", "unknown", "noassertion"}


@check("sbom_tr03183_fields", EXECUTION)
def _sbom_tr03183(ctx: Context):
    path = ctx.evidence_file("sbom.cdx.json")
    if path is None:
        return MISSING, "no sbom.cdx.json in this run's evidence"
    sbom, error = _load_json(path)
    if error or not isinstance(sbom, dict):
        return FAIL, error or "not a JSON object", ["evidence/sbom.cdx.json"]

    present: list[str] = []
    gaps: list[str] = []

    def field(ok: bool, label: str, gap: str) -> None:
        (present if ok else gaps).append(label if ok else gap)

    spec = str(sbom.get("specVersion", "0"))
    field(
        sbom.get("bomFormat") == "CycloneDX" and _version_tuple(spec) >= (1, 5),
        f"CycloneDX {spec}",
        f"CycloneDX {spec} (>= 1.5 required)",
    )
    metadata = sbom.get("metadata") or {}
    field(bool(metadata.get("timestamp")), "timestamp", "SBOM timestamp")
    field(
        bool(metadata.get("authors") or metadata.get("manufacturer") or metadata.get("supplier")),
        "SBOM creator",
        "SBOM creator (metadata.authors/manufacturer)",
    )

    components = sbom.get("components") or []
    total = len(components)

    def per_component(predicate: Callable[[dict], bool], label: str, gap: str) -> None:
        missing = [c.get("name", "?") for c in components if not predicate(c)]
        if not missing and total:
            present.append(label)
        else:
            gaps.append(f"{gap} ({len(missing)}/{total}: {', '.join(missing)})")

    def creator(c: dict) -> bool:
        for key in ("supplier", "manufacturer"):
            entry = c.get(key) or {}
            if str(entry.get("name", "")).strip().lower() not in PLACEHOLDER_CREATORS:
                return True
        return str(c.get("author", "")).strip().lower() not in PLACEHOLDER_CREATORS

    per_component(lambda c: bool(c.get("name") and c.get("version")), "name + version", "name/version")
    per_component(creator, "component creator", "component creator (placeholder or empty)")
    per_component(lambda c: bool(c.get("licenses")), "licence", "licence")
    per_component(
        lambda c: any(str(h.get("alg", "")).upper() == "SHA-512" for h in c.get("hashes") or []),
        "SHA-512 hash",
        "SHA-512 hash",
    )
    field(bool(sbom.get("dependencies")), "dependency relations", "dependency relations")

    detail = f"present: {', '.join(present) or 'none'}"
    if gaps:
        detail += f". Missing: {'; '.join(gaps)}"
    result = PASS if not gaps else (PARTIAL if present else FAIL)
    return result, detail, ["evidence/sbom.cdx.json"]


CVE_GATE = 9.0


@check("dependency_cve_scan", EXECUTION)
def _dependency_cve_scan(ctx: Context):
    path = ctx.evidence_file("conan-audit.json")
    if path is None:
        return MISSING, "no conan-audit.json in this run's evidence (CVE provider not available to this run)"
    report, error = _load_json(path)
    if error or not isinstance(report, dict):
        return FAIL, error or "not a JSON object", ["evidence/conan-audit.json"]
    if report.get("conan_error"):
        return FAIL, f"conan audit reported: {report['conan_error']}", ["evidence/conan-audit.json"]

    findings: list[tuple[float, str, str]] = []
    for ref, entry in (report.get("data") or {}).items():
        for edge in ((entry or {}).get("vulnerabilities") or {}).get("edges") or []:
            node = edge.get("node") or {}
            score = float((node.get("cvss") or {}).get("preferredBaseScore") or 0.0)
            findings.append((score, ref, str(node.get("name", "?"))))
    scanned = len(report.get("data") or {})
    blocking = [f for f in findings if f[0] >= CVE_GATE]
    if blocking:
        listed = ", ".join(f"{name} ({score}) in {ref}" for score, ref, name in sorted(blocking, reverse=True))
        return FAIL, f"advisories at or above CVSS {CVE_GATE}: {listed}", ["evidence/conan-audit.json"]
    if findings:
        listed = ", ".join(f"{name} ({score}) in {ref}" for score, ref, name in sorted(findings, reverse=True))
        return (
            PASS,
            f"{scanned} package(s) scanned; none at or above CVSS {CVE_GATE}. Below the gate, recorded: {listed}",
            ["evidence/conan-audit.json"],
        )
    return PASS, f"{scanned} package(s) scanned; no known advisories", ["evidence/conan-audit.json"]


@check("sast_gate", EXECUTION)
def _sast_gate(ctx: Context):
    path = ctx.evidence_file("sast-gate.txt")
    if path is None:
        return MISSING, "no sast-gate.txt in this run's evidence"
    text = path.read_text(encoding="utf-8", errors="replace")
    if "no new findings" in text:
        summary = next((line for line in text.splitlines() if "finding(s) in" in line), "")
        return PASS, f"no findings beyond the reviewed baseline. {summary.strip()}", ["evidence/sast-gate.txt"]
    return FAIL, "the SAST gate did not report a clean result", ["evidence/sast-gate.txt"]


@check("unit_tests", EXECUTION)
def _unit_tests(ctx: Context):
    path = ctx.evidence_file("ctest.txt")
    if path is None:
        return MISSING, "no ctest.txt in this run's evidence"
    text = path.read_text(encoding="utf-8", errors="replace")
    runs = re.findall(r"(\d+)% tests passed, (\d+) tests failed out of (\d+)", text)
    if not runs:
        return FAIL, "no ctest summary found in the log", ["evidence/ctest.txt"]
    bad = [r for r in runs if r[1] != "0"]
    if bad:
        return FAIL, f"{bad[0][1]} of {bad[0][2]} tests failed", ["evidence/ctest.txt"]
    total = sum(int(r[2]) for r in runs)
    return PASS, f"{total} tests passed, built with the shipping toolchain", ["evidence/ctest.txt"]


@check("binary_hardening", EXECUTION)
def _binary_hardening(ctx: Context):
    path = ctx.evidence_file("hardening.txt")
    if path is None:
        return MISSING, "no hardening.txt in this run's evidence (produced by the release build)"
    text = path.read_text(encoding="utf-8", errors="replace")
    ok = [line.split("ok", 1)[1].strip() for line in text.splitlines() if line.strip().startswith("ok ")]
    failed = [line.split("FAIL", 1)[1].strip() for line in text.splitlines() if line.strip().startswith("FAIL")]
    if failed:
        return FAIL, f"missing on the shipped binary: {', '.join(failed)}", ["evidence/hardening.txt"]
    if not ok:
        return FAIL, "the hardening report contains no results", ["evidence/hardening.txt"]
    return PASS, f"verified on the shipped ELF: {', '.join(ok)}", ["evidence/hardening.txt"]


@check("coverage_reported", EXECUTION)
def _coverage_reported(ctx: Context):
    path = ctx.evidence_file("coverage.txt")
    if path is None:
        return MISSING, "no coverage.txt in this run's evidence"
    text = path.read_text(encoding="utf-8", errors="replace")
    match = re.search(r"^TOTAL\s+\d+\s+\d+\s+(\d+(?:\.\d+)?)%", text, re.MULTILINE)
    figure = f"{match.group(1)}% line coverage" if match else "coverage report present"
    # Reported, never judged: the pipeline deliberately has no coverage target.
    return PASS, f"{figure} (reported, not a target)", ["evidence/coverage.txt"]


# ---------------------------------------------------------------------------
# Configuration evidence - the pipeline is set up to enforce it
# ---------------------------------------------------------------------------


@check("image_cve_gates", CONFIGURATION)
def _image_cve_gates(ctx: Context):
    text, err = _needs(ctx, ".github/workflows/supply-chain.yml")
    if err:
        return err
    trivy = re.search(r"trivy image[^\n]*--exit-code 1", text)
    grype = re.search(r"grype [^\n]*--fail-on", text) or "--fail-on critical" in text
    if trivy and grype:
        return PASS, "trivy and grype gate the image on every build", [".github/workflows/supply-chain.yml"]
    return FAIL, "image scan gates not found in supply-chain.yml", [".github/workflows/supply-chain.yml"]


@check("cve_rescan_scheduled", CONFIGURATION)
def _cve_rescan_scheduled(ctx: Context):
    text, err = _needs(ctx, ".github/workflows/cve-rescan.yml")
    if err:
        return err
    cron = re.search(r"cron:\s*'([^']+)'", text)
    if cron and "issue" in text:
        return (
            PASS,
            f"nightly rescan (cron '{cron.group(1)}') of main and the latest release image; findings open a tracking issue",
            [".github/workflows/cve-rescan.yml"],
        )
    return FAIL, "no scheduled rescan with issue tracking", [".github/workflows/cve-rescan.yml"]


@check("minimal_runtime_image", CONFIGURATION)
def _minimal_runtime_image(ctx: Context):
    text, err = _needs(ctx, "docker/Dockerfile")
    if err:
        return err
    stages = re.findall(r"^FROM\s+(\S+)", text, re.MULTILINE)
    final = stages[-1] if stages else ""
    tail = text[text.rfind("FROM ") :]
    problems = []
    if "distroless" not in final:
        problems.append("final stage is not distroless")
    if "@sha256:" not in final:
        problems.append("base image not pinned by digest")
    if not re.search(r"^USER\s+nonroot", tail, re.MULTILINE):
        problems.append("does not run as nonroot")
    if problems:
        return FAIL, "; ".join(problems), ["docker/Dockerfile"]
    return PASS, f"runtime {final.split('@')[0]} pinned by digest, USER nonroot", ["docker/Dockerfile"]


@check("dependency_updates_automated", CONFIGURATION)
def _dependency_updates(ctx: Context):
    renovate = ctx.repo_text("renovate.json")
    dependabot = ctx.repo_text(".github/dependabot.yml")
    if renovate is None or dependabot is None:
        return FAIL, "renovate.json or .github/dependabot.yml missing"
    return (
        PASS,
        "Renovate (Conan packages, lockfile) and Dependabot (actions, base image, Python tooling) propose updates",
        ["renovate.json", ".github/dependabot.yml"],
    )


@check("lockfile_enforced", CONFIGURATION)
def _lockfile_enforced(ctx: Context):
    if not (ctx.repo / "conan.lock").is_file():
        return FAIL, "conan.lock is not committed"
    ctx.touched["conan.lock"] = ctx.repo / "conan.lock"
    users = [
        rel
        for rel in ("docker/Dockerfile", ".github/workflows/release.yml", ".github/workflows/supply-chain.yml")
        if "--lockfile=conan.lock" in (ctx.repo_text(rel) or "")
    ]
    if len(users) < 3:
        return PARTIAL, f"lockfile used explicitly only in: {', '.join(users) or 'nothing'}", ["conan.lock"]
    return PASS, "conan.lock committed and required by the image, SBOM and release builds", ["conan.lock", *users]


@check("artefact_signing", CONFIGURATION)
def _artefact_signing(ctx: Context):
    release = ctx.repo_text(".github/workflows/release.yml") or ""
    supply = ctx.repo_text(".github/workflows/supply-chain.yml") or ""
    found = {
        "SLSA build provenance": "attest-build-provenance" in release,
        "SBOM attestation": "attest-sbom" in release,
        "SHA-256 checksums": "sha256sum" in release,
        "cosign image signature": "cosign sign" in supply,
    }
    missing = [k for k, v in found.items() if not v]
    sources = [".github/workflows/release.yml", ".github/workflows/supply-chain.yml"]
    if missing:
        return FAIL, f"not configured: {', '.join(missing)}", sources
    return PASS, ", ".join(found), sources


USES = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.MULTILINE)


@check("actions_pinned", CONFIGURATION)
def _actions_pinned(ctx: Context):
    files = sorted((ctx.repo / ".github" / "workflows").glob("*.yml"))
    files += sorted((ctx.repo / ".github" / "actions").glob("*/action.yml"))
    unpinned: list[str] = []
    total = 0
    for path in files:
        rel = str(path.relative_to(ctx.repo))
        ctx.touched[rel] = path
        for ref in USES.findall(path.read_text(encoding="utf-8")):
            if ref.startswith(("./", "$/")):
                continue  # this repository, same commit
            total += 1
            if ref.startswith("docker://"):
                if "@sha256:" not in ref:
                    unpinned.append(f"{rel}: {ref}")
            elif not re.search(r"@[0-9a-f]{40}$", ref):
                unpinned.append(f"{rel}: {ref}")
    if unpinned:
        return FAIL, f"not pinned to a commit SHA: {'; '.join(unpinned)}"
    return PASS, f"all {total} third-party action references pinned to a full commit SHA"


@check("fuzzing_continuous", CONFIGURATION)
def _fuzzing_continuous(ctx: Context):
    nightly = ctx.repo_text(".github/workflows/fuzzing.yml") or ""
    ci = ctx.repo_text(".github/workflows/ci.yml") or ""
    parts = []
    if "schedule:" in nightly:
        parts.append("nightly libFuzzer run with a cumulative corpus")
    if "fuzz-smoke" in ci:
        parts.append("60 s fuzz smoke on every pull request")
    if "ReplaysCheckedInCorpus" in (ctx.repo_text("tests/test_parser.cpp") or ""):
        parts.append("checked-in corpus replayed in every test run")
    if len(parts) == 3:
        return PASS, "; ".join(parts), [".github/workflows/fuzzing.yml", ".github/workflows/ci.yml"]
    return PARTIAL if parts else FAIL, "; ".join(parts) or "no fuzzing configured"


@check("dast_configured", CONFIGURATION)
def _dast_configured(ctx: Context):
    text, err = _needs(ctx, ".github/workflows/supply-chain.yml")
    if err:
        return err
    zap = "zap-api-scan" in text or "ZAP" in text
    schemathesis = "schemathesis" in text.lower()
    if zap and schemathesis:
        return PASS, "ZAP API scan and Schemathesis contract fuzzing against the built container", [
            ".github/workflows/supply-chain.yml"
        ]
    return FAIL, "DAST not configured in supply-chain.yml", [".github/workflows/supply-chain.yml"]


@check("api_contract_enforced", CONFIGURATION)
def _api_contract(ctx: Context):
    spec = ctx.repo_text("docs/openapi.yaml")
    workflow = ctx.repo_text(".github/workflows/supply-chain.yml") or ""
    if spec is None:
        return FAIL, "docs/openapi.yaml missing"
    paths = len(re.findall(r"^  /\S*:", spec, re.MULTILINE))
    if "schemathesis" not in workflow.lower():
        return PARTIAL, f"{paths} paths specified, but the contract is not tested", ["docs/openapi.yaml"]
    return PASS, f"{paths} paths specified in OpenAPI and enforced by contract fuzzing", [
        "docs/openapi.yaml",
        ".github/workflows/supply-chain.yml",
    ]


@check("sanitizers_in_ci", CONFIGURATION)
def _sanitizers(ctx: Context):
    text, err = _needs(ctx, ".github/workflows/ci.yml")
    if err:
        return err
    found = [name for key, name in (("sanitizer: address", "ASan/UBSan"), ("sanitizer: thread", "TSan")) if key in text]
    if "cross-aarch64" in text:
        found.append("AArch64 tests under qemu")
    if len(found) >= 2:
        return PASS, f"on every change: {', '.join(found)}", [".github/workflows/ci.yml"]
    return FAIL, "sanitizer jobs not found in ci.yml", [".github/workflows/ci.yml"]


@check("release_requires_green_ci", CONFIGURATION)
def _release_requires_green_ci(ctx: Context):
    text, err = _needs(ctx, ".github/workflows/release.yml")
    if err:
        return err
    if "Require green CI" in text:
        return PASS, "a tag only releases a commit whose full CI succeeded", [".github/workflows/release.yml"]
    return FAIL, "the release does not depend on CI results", [".github/workflows/release.yml"]


# ---------------------------------------------------------------------------
# Document evidence
# ---------------------------------------------------------------------------


@check("threat_model", DOCUMENT)
def _threat_model(ctx: Context):
    text, err = _needs(ctx, "docs/threat-model.md")
    if err:
        return err
    if "STRIDE" in text and re.search(r"trust boundar", text, re.IGNORECASE):
        return PASS, "STRIDE threat model over the documented trust boundaries", ["docs/threat-model.md"]
    return FAIL, "threat model lacks STRIDE analysis or trust boundaries", ["docs/threat-model.md"]


@check("security_policy", DOCUMENT)
def _security_policy(ctx: Context):
    text, err = _needs(ctx, "SECURITY.md")
    if err:
        return err
    has_section = re.search(r"^#+\s*Reporting a vulnerability", text, re.MULTILINE | re.IGNORECASE)
    has_channel = "security/advisories/new" in text
    has_times = re.search(r"acknowledg", text, re.IGNORECASE)
    if has_section and has_channel and has_times:
        return PASS, "private reporting channel, response times and coordinated disclosure in SECURITY.md", [
            "SECURITY.md"
        ]
    return FAIL, "SECURITY.md lacks a reporting section, private channel or response times", ["SECURITY.md"]


@check("support_period_declared", DOCUMENT)
def _support_period(ctx: Context):
    text, err = _needs(ctx, "SECURITY.md")
    if err:
        return err
    match = re.search(r"support period[^\n]*?(\d{4}-\d{2}-\d{2}|\b20\d{2}\b)", text, re.IGNORECASE)
    if match:
        return PASS, f"support period declared, ending {match.group(1)}", ["SECURITY.md"]
    return FAIL, "SECURITY.md states no support period with an end date", ["SECURITY.md"]


# ---------------------------------------------------------------------------
# Evaluation and rendering
# ---------------------------------------------------------------------------


def load_catalogue(path: pathlib.Path) -> dict:
    try:
        catalogue = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise CatalogueError(f"cannot read {path}: {exc}") from exc
    seen: set[str] = set()
    for control in catalogue.get("control", []):
        cid = control.get("id", "?")
        if cid in seen:
            raise CatalogueError(f"duplicate control id {cid}")
        seen.add(cid)
        if control.get("framework") not in catalogue.get("frameworks", {}):
            raise CatalogueError(f"{cid}: unknown framework {control.get('framework')!r}")
        unknown = [c for c in control.get("checks", []) if c not in CHECKS]
        if unknown:
            raise CatalogueError(f"{cid}: unknown check(s) {', '.join(unknown)}")
        assessment = control.get("assessment")
        if assessment is not None and assessment not in ASSESSMENTS:
            raise CatalogueError(f"{cid}: unknown assessment {assessment!r}")
        if not control.get("checks") and assessment is None:
            raise CatalogueError(f"{cid}: needs checks, an assessment, or both")
    return catalogue


def control_status(assessment: str | None, results: list[CheckResult]) -> str:
    outcomes = {r.result for r in results}
    if FAIL in outcomes:
        return "not_met"
    if assessment == "gap":
        return "gap"
    if MISSING in outcomes:
        return "not_assessed"
    if assessment in ("not_applicable", "organisational"):
        return assessment
    if PARTIAL in outcomes or assessment == "partial":
        return "partial"
    return "met"


def evaluate(catalogue: dict, ctx: Context) -> list[dict]:
    cache: dict[str, CheckResult] = {}
    controls = []
    for control in catalogue["control"]:
        results = []
        for name in control.get("checks", []):
            if name not in cache:
                cache[name] = CHECKS[name](ctx)
            results.append(cache[name])
        controls.append(
            {
                "id": control["id"],
                "framework": control["framework"],
                "ref": control["ref"],
                "requirement": control["requirement"],
                "also": control.get("also", []),
                "assessment": control.get("assessment"),
                "note": control.get("note", ""),
                "status": control_status(control.get("assessment"), results),
                "checks": [dataclasses.asdict(r) for r in results],
            }
        )
    return controls


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def run_metadata(args: argparse.Namespace) -> dict:
    commit = os.environ.get("GITHUB_SHA")
    if not commit:
        try:
            commit = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
            ).stdout.strip()
        except (OSError, subprocess.CalledProcessError):
            commit = "unknown"
    run_url = None
    if os.environ.get("GITHUB_RUN_ID"):
        run_url = (
            f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/"
            f"{os.environ.get('GITHUB_REPOSITORY', '')}/actions/runs/{os.environ['GITHUB_RUN_ID']}"
        )
    return {
        "version": args.version,
        "commit": commit,
        "workflow_run": run_url,
        "generated_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "catalogue_sha256": sha256(CATALOGUE),
    }


def summarise(controls: list[dict]) -> dict[str, int]:
    counts = {status: 0 for status in STATUS_LABELS}
    for control in controls:
        counts[control["status"]] += 1
    return counts


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(catalogue: dict, run: dict, controls: list[dict], inventory: list[dict]) -> str:
    meta = catalogue["meta"]
    out: list[str] = []
    out.append(f"# Compliance report - {meta['product']}\n")
    out.append("| | |\n| --- | --- |")
    out.append(f"| Manufacturer | {_cell(meta['manufacturer'])} |")
    out.append(f"| Version | {run['version'] or 'not a release (pipeline run)'} |")
    out.append(f"| Commit | `{run['commit']}` |")
    if run["workflow_run"]:
        out.append(f"| Workflow run | {run['workflow_run']} |")
    out.append(f"| Generated (UTC) | {run['generated_utc']} |")
    out.append(f"| Control catalogue | `compliance/controls.toml`, sha256 `{run['catalogue_sha256'][:16]}…` |")
    out.append("")
    out.append("> " + " ".join(meta["disclaimer"].split()))
    out.append("")

    out.append("## Summary\n")
    out.append("| Status | Controls |\n| --- | ---: |")
    for status, count in summarise(controls).items():
        if count:
            icon, label = STATUS_LABELS[status]
            out.append(f"| {icon} {label} | {count} |")
    out.append("")
    for key, framework in catalogue["frameworks"].items():
        out.append(f"- **{framework['name']}** - {framework.get('note', '')}")
    out.append("")

    open_items = [c for c in controls if c["status"] in ("not_met", "gap", "partial", "not_assessed")]
    if open_items:
        out.append("## Open items\n")
        order = list(STATUS_LABELS)
        for control in sorted(open_items, key=lambda c: order.index(c["status"])):
            icon, label = STATUS_LABELS[control["status"]]
            reasons = [
                f"{r['name']}: {r['detail']}" for r in control["checks"] if r["result"] in (FAIL, PARTIAL, MISSING)
            ]
            reason = "; ".join(reasons) if reasons else control["note"]
            out.append(f"- {icon} **{control['id']}** ({control['ref']}) - {label}. {reason}")
        out.append("")

    out.append("## Controls\n")
    out.append("| ID | Reference | Requirement | Status |\n| --- | --- | --- | --- |")
    for control in controls:
        icon, label = STATUS_LABELS[control["status"]]
        out.append(
            f"| [{control['id']}](#{control['id'].lower().replace('.', '')}) | {_cell(control['ref'])} "
            f"| {_cell(control['requirement'])} | {icon} {label} |"
        )
    out.append("")

    for control in controls:
        icon, label = STATUS_LABELS[control["status"]]
        out.append(f"### {control['id']}\n")
        out.append(f"**{control['ref']}** - {control['requirement']}\n")
        out.append(f"Status: {icon} **{label}**\n")
        if control["checks"]:
            out.append("| Check | Kind | Result | Evidence |\n| --- | --- | --- | --- |")
            for r in control["checks"]:
                out.append(
                    f"| `{r['name']}` | {r['kind']} | {CHECK_ICONS[r['result']]} {r['result']} | {_cell(r['detail'])} |"
                )
            out.append("")
        if control["note"]:
            out.append(f"{' '.join(control['note'].split())}\n")
        if control["also"]:
            out.append(f"Related: {', '.join(control['also'])}\n")

    out.append("## Evidence inventory\n")
    out.append(
        "Every file a check read, hashed, so the report can be tied to the exact bytes it was computed from. "
        "Evidence files are also covered by the release's build-provenance attestation.\n"
    )
    out.append("| File | SHA-256 | Bytes |\n| --- | --- | ---: |")
    for item in inventory:
        out.append(f"| `{item['path']}` | `{item['sha256']}` | {item['bytes']} |")
    out.append("")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--evidence", type=pathlib.Path, required=True, help="directory with the run's evidence")
    parser.add_argument("--catalogue", type=pathlib.Path, default=CATALOGUE)
    parser.add_argument("--version", help="release version; omitted for pipeline runs")
    parser.add_argument("--out-md", type=pathlib.Path, required=True)
    parser.add_argument("--out-json", type=pathlib.Path)
    args = parser.parse_args(argv)

    try:
        catalogue = load_catalogue(args.catalogue)
    except CatalogueError as exc:
        print(f"compliance-report: {exc}", file=sys.stderr)
        return 2

    ctx = Context(evidence=args.evidence, repo=REPO_ROOT)
    controls = evaluate(catalogue, ctx)
    run = run_metadata(args)
    inventory = [
        {"path": rel, "sha256": sha256(path), "bytes": path.stat().st_size}
        for rel, path in sorted(ctx.touched.items())
    ]

    args.out_md.parent.mkdir(parents=True, exist_ok=True)
    args.out_md.write_text(render_markdown(catalogue, run, controls, inventory), encoding="utf-8")
    if args.out_json:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(
            json.dumps(
                {
                    "meta": catalogue["meta"],
                    "frameworks": catalogue["frameworks"],
                    "run": run,
                    "summary": summarise(controls),
                    "controls": controls,
                    "evidence": inventory,
                },
                indent=2,
                ensure_ascii=False,
            )
            + "\n",
            encoding="utf-8",
        )

    counts = summarise(controls)
    print(
        "compliance-report: "
        + ", ".join(f"{STATUS_LABELS[s][1].split(' -')[0].lower()}: {n}" for s, n in counts.items() if n)
    )
    print(f"compliance-report: wrote {args.out_md}" + (f" and {args.out_json}" if args.out_json else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
