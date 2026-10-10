#!/usr/bin/env python3
"""Assemble a pipeline run's evidence and render its final report.

    # 1. one flat evidence directory from the run's downloaded artefacts
    scripts/pipeline_report.py assemble --artifacts artifacts --out evidence

    # 2. (scripts/compliance_report.py --evidence evidence ...)

    # 3. the final report: gates, key figures, compliance, inventory
    scripts/pipeline_report.py render --evidence evidence --jobs jobs.jsonl \\
        --out-md evidence/pipeline-report.md --out-json evidence/pipeline-report.json

Used by the `report` job in .github/workflows/pipeline.yml. Each job of the
run uploads what it observed as an artefact; `assemble` maps those artefacts
onto the flat layout scripts/compliance_report.py reads (the same layout as
the release evidence bundle), and `render` turns the result into one report.

The report records, it does not judge. Every verdict in it comes from a gate
job (via the jobs API) or from the evidence the gates produced. A figure that
could not be read says so - "not produced in this run" - rather than
defaulting to zero, because a zero is a claim.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import shutil
import sys
import xml.etree.ElementTree as ET

NOT_PRODUCED = "not produced in this run"

# Artefact name -> files copied verbatim into the evidence directory. Paths
# are relative to the artefact's directory after download.
VERBATIM = {
    "dependency-evidence": ["sbom.cdx.json", "conan-audit.json", "licenses.json", "conan.lock"],
    "image-evidence": [
        "image-sbom.cdx.json",
        "grype-image.json",
        "zap-report.json",
        "zap-report.html",
        "schemathesis-junit.xml",
    ],
    "static-analysis-reports": ["clang-tidy.txt", "cppcheck.txt", "sast-gate.txt"],
    "coverage-report": ["coverage.txt", "coverage.xml"],
}

# Artefacts whose ctest.txt / hardening.txt are concatenated into one file
# each. Every test run counts: x86-64, macOS, AArch64 under qemu, and the
# sanitizer builds are the same suite under different conditions.
TEST_RUNS = "evidence-build-*", "evidence-cross-aarch64", "evidence-sanitize-*"


def _copy(src: pathlib.Path, dst: pathlib.Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def assemble(artifacts: pathlib.Path, out: pathlib.Path) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    present = sorted(p.name for p in artifacts.iterdir() if p.is_dir()) if artifacts.is_dir() else []
    copied: list[str] = []

    for artefact, files in VERBATIM.items():
        for name in files:
            src = artifacts / artefact / name
            if src.is_file():
                _copy(src, out / name)
                copied.append(name)

    for kind in ("ctest.txt", "hardening.txt"):
        sections = []
        for pattern in TEST_RUNS:
            for directory in sorted(artifacts.glob(pattern)):
                src = directory / kind
                if src.is_file():
                    _copy(src, out / "runs" / directory.name / kind)
                    sections.append(f"### {directory.name}\n{src.read_text(encoding='utf-8', errors='replace')}")
        if sections:
            (out / kind).write_text("\n".join(sections), encoding="utf-8")
            copied.append(kind)

    fuzz = artifacts / "evidence-fuzz-smoke"
    if (fuzz / "evidence" / "fuzz-smoke.txt").is_file():
        _copy(fuzz / "evidence" / "fuzz-smoke.txt", out / "fuzz-smoke.txt")
        copied.append("fuzz-smoke.txt")
    reproducers = sorted((fuzz / "artifacts").glob("*")) if (fuzz / "artifacts").is_dir() else []
    for reproducer in reproducers:
        _copy(reproducer, out / "fuzz-reproducers" / reproducer.name)

    manifest = {"artifacts": present, "files": copied, "fuzz_reproducers": [p.name for p in reproducers]}
    (out / "assembly.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"pipeline-report: {len(present)} artefact(s) -> {len(copied)} evidence file(s) in {out}")
    return manifest


# ---------------------------------------------------------------------------
# Key figures. Each reader returns a short string, or NOT_PRODUCED.
# ---------------------------------------------------------------------------


def _read_json(path: pathlib.Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def fig_tests(ev: pathlib.Path) -> str:
    runs_dir = ev / "runs"
    if not runs_dir.is_dir():
        return NOT_PRODUCED
    parts, total, failed = [], 0, 0
    for run in sorted(runs_dir.iterdir()):
        log = run / "ctest.txt"
        if not log.is_file():
            continue
        match = re.search(r"(\d+)% tests passed, (\d+) tests failed out of (\d+)", log.read_text(errors="replace"))
        if match:
            total += int(match.group(3))
            failed += int(match.group(2))
            parts.append(f"{run.name.removeprefix('evidence-')} {match.group(3)}")
        else:
            parts.append(f"{run.name.removeprefix('evidence-')} (no summary)")
    if not parts:
        return NOT_PRODUCED
    return f"{total - failed}/{total} passed across {len(parts)} runs ({', '.join(parts)})"


def fig_coverage(ev: pathlib.Path) -> str:
    path = ev / "coverage.txt"
    if not path.is_file():
        return NOT_PRODUCED
    match = re.search(r"^TOTAL\s+(\d+)\s+(\d+)\s+(\d+(?:\.\d+)?)%", path.read_text(errors="replace"), re.MULTILINE)
    return f"{match.group(3)}% of {match.group(1)} lines (reported, not a target)" if match else "report present"


def fig_sast(ev: pathlib.Path) -> str:
    path = ev / "sast-gate.txt"
    if not path.is_file():
        return NOT_PRODUCED
    text = path.read_text(errors="replace")
    found = re.search(r"sast-gate: (\d+) finding\(s\)", text)
    base = re.search(r"baseline accounts for (\d+)", text)
    verdict = "no new findings" if "no new findings" in text else "NEW FINDINGS"
    return f"{verdict}; {found.group(1) if found else '?'} current, {base.group(1) if base else '?'} in the baseline"


def fig_dependency_cves(ev: pathlib.Path) -> str:
    report = _read_json(ev / "conan-audit.json")
    if not isinstance(report, dict):
        return NOT_PRODUCED
    if report.get("conan_error"):
        return f"scan failed: {report['conan_error']}"
    data = report.get("data") or {}
    scores = [
        float(((edge.get("node") or {}).get("cvss") or {}).get("preferredBaseScore") or 0)
        for entry in data.values()
        for edge in (((entry or {}).get("vulnerabilities") or {}).get("edges") or [])
    ]
    if not scores:
        return f"{len(data)} packages scanned, no known advisories"
    return f"{len(data)} packages scanned, {len(scores)} advisories, highest CVSS {max(scores)}"


def fig_licences(ev: pathlib.Path) -> str:
    report = _read_json(ev / "licenses.json")
    if not isinstance(report, dict):
        return NOT_PRODUCED
    verdicts = [c.get("verdict") for c in report.get("components", [])]
    denied = verdicts.count("DENIED")
    listed = ", ".join(f"{c.get('ref')} ({c.get('license')})" for c in report.get("components", []))
    return f"{len(verdicts) - denied}/{len(verdicts)} allowed: {listed}" if verdicts else "no components"


def fig_sbom(ev: pathlib.Path, name: str) -> str:
    sbom = _read_json(ev / name)
    if not isinstance(sbom, dict):
        return NOT_PRODUCED
    return f"CycloneDX {sbom.get('specVersion', '?')}, {len(sbom.get('components') or [])} components"


def fig_image_vulns(ev: pathlib.Path) -> str:
    report = _read_json(ev / "grype-image.json")
    if not isinstance(report, dict):
        return NOT_PRODUCED
    counts: dict[str, int] = {}
    fixable_critical = 0
    for match in report.get("matches") or []:
        vuln = match.get("vulnerability") or {}
        severity = str(vuln.get("severity", "Unknown"))
        counts[severity] = counts.get(severity, 0) + 1
        if severity == "Critical" and (vuln.get("fix") or {}).get("state") == "fixed":
            fixable_critical += 1
    if not counts:
        return "grype: no known vulnerabilities in the image"
    order = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]
    listed = ", ".join(f"{counts[s]} {s.lower()}" for s in order if s in counts)
    return f"grype: {listed}; {fixable_critical} critical with a fix (gate)"


def fig_zap(ev: pathlib.Path) -> str:
    report = _read_json(ev / "zap-report.json")
    if not isinstance(report, dict):
        return NOT_PRODUCED
    counts: dict[str, int] = {}
    for site in report.get("site") or []:
        for alert in site.get("alerts") or []:
            risk = str(alert.get("riskdesc", "?")).split(" ")[0]
            counts[risk] = counts.get(risk, 0) + 1
    if not counts:
        return "no alerts"
    return ", ".join(f"{n} {risk.lower()}" for risk, n in sorted(counts.items())) + " (judged against .zap/rules.tsv)"


def fig_schemathesis(ev: pathlib.Path) -> str:
    path = ev / "schemathesis-junit.xml"
    if not path.is_file():
        return NOT_PRODUCED
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return "report unreadable"
    suites = [root] if root.tag == "testsuite" else root.findall("testsuite")
    tests = sum(int(s.get("tests", 0)) for s in suites)
    failures = sum(int(s.get("failures", 0)) + int(s.get("errors", 0)) for s in suites)
    return f"{tests - failures}/{tests} operations conform to the OpenAPI contract"


def fig_fuzz(ev: pathlib.Path) -> str:
    path = ev / "fuzz-smoke.txt"
    if not path.is_file():
        return NOT_PRODUCED
    text = path.read_text(errors="replace")
    runs = re.search(r"stat::number_of_executed_units:\s*(\d+)", text)
    reproducers = list((ev / "fuzz-reproducers").glob("*")) if (ev / "fuzz-reproducers").is_dir() else []
    executed = f"{int(runs.group(1)):,} inputs executed" if runs else "run statistics missing"
    return f"{executed}, {len(reproducers)} crash reproducer(s)"


def fig_hardening(ev: pathlib.Path) -> str:
    runs_dir = ev / "runs"
    parts = []
    for log in sorted(runs_dir.glob("*/hardening.txt")) if runs_dir.is_dir() else []:
        text = log.read_text(errors="replace")
        ok = len(re.findall(r"^\s*ok\s", text, re.MULTILINE))
        fail = len(re.findall(r"^\s*FAIL\s", text, re.MULTILINE))
        parts.append(f"{log.parent.name.removeprefix('evidence-')}: {ok} ok, {fail} missing")
    return "; ".join(parts) if parts else NOT_PRODUCED


FIGURES = [
    ("Unit tests", fig_tests),
    ("Coverage", fig_coverage),
    ("Static analysis", fig_sast),
    ("Fuzzing (PR smoke)", fig_fuzz),
    ("ELF hardening", fig_hardening),
    ("Dependency CVEs", fig_dependency_cves),
    ("Licences", fig_licences),
    ("SBOM (dependencies)", lambda ev: fig_sbom(ev, "sbom.cdx.json")),
    ("SBOM (image)", lambda ev: fig_sbom(ev, "image-sbom.cdx.json")),
    ("Image vulnerabilities", fig_image_vulns),
    ("DAST (ZAP)", fig_zap),
    ("API contract (Schemathesis)", fig_schemathesis),
]


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

JOB_ICONS = {"success": "✅", "failure": "❌", "cancelled": "⏹️", "skipped": "⏭️", "timed_out": "⌛"}


def load_jobs(path: pathlib.Path) -> list[dict]:
    jobs = []
    if not path.is_file():
        return jobs
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            jobs.append(json.loads(line))
    return jobs


def _duration(job: dict) -> str:
    try:
        start = dt.datetime.fromisoformat(job["started_at"].replace("Z", "+00:00"))
        end = dt.datetime.fromisoformat(job["completed_at"].replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError, AttributeError):
        return ""
    seconds = int((end - start).total_seconds())
    return f"{seconds // 60}m {seconds % 60:02d}s"


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def render(evidence: pathlib.Path, jobs_path: pathlib.Path, out_md: pathlib.Path, out_json: pathlib.Path | None) -> int:
    own_name = os.environ.get("TTG_REPORT_JOB", "Pipeline report")
    jobs = [j for j in load_jobs(jobs_path) if j.get("name") != own_name]
    finished = [j for j in jobs if j.get("status") == "completed"]
    failed = [j for j in finished if j.get("conclusion") in ("failure", "timed_out", "cancelled")]

    figures = {label: reader(evidence) for label, reader in FIGURES}
    compliance = _read_json(evidence / "compliance-report.json") or {}
    assembly = _read_json(evidence / "assembly.json") or {}

    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    run_id = os.environ.get("GITHUB_RUN_ID")
    run = {
        "repository": repo,
        "ref": os.environ.get("GITHUB_REF", ""),
        "event": os.environ.get("GITHUB_EVENT_NAME", ""),
        "commit": os.environ.get("GITHUB_SHA", ""),
        "workflow_run": f"{server}/{repo}/actions/runs/{run_id}" if run_id else None,
        "generated_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    if not jobs:
        verdict = "⚪ No job results available - the verdict could not be determined"
    elif failed:
        verdict = f"❌ **{len(failed)} of {len(finished)} gate jobs failed**"
    else:
        verdict = f"✅ **All {len(finished)} gate jobs passed**"

    md: list[str] = ["# Pipeline report\n"]
    md.append("| | |\n| --- | --- |")
    md.append(f"| Repository | {repo} |")
    md.append(f"| Ref / event | `{run['ref']}` / {run['event']} |")
    md.append(f"| Commit | `{run['commit']}` |")
    if run["workflow_run"]:
        md.append(f"| Workflow run | {run['workflow_run']} |")
    md.append(f"| Generated (UTC) | {run['generated_utc']} |")
    md.append("")
    md.append(f"{verdict}\n")

    if failed:
        md.append("Failed: " + ", ".join(f"[{j['name']}]({j.get('html_url', '')})" for j in failed) + "\n")

    md.append("## Key figures\n")
    md.append("| Area | Result |\n| --- | --- |")
    for label, value in figures.items():
        md.append(f"| {label} | {value.replace('|', '/')} |")
    md.append("")

    summary = compliance.get("summary") or {}
    if summary:
        labels = {
            "met": "✅ met",
            "partial": "🟡 partially met",
            "not_met": "❌ not met",
            "gap": "🔴 known gap",
            "not_assessed": "⚪ not assessed",
            "organisational": "📋 organisational",
            "not_applicable": "➖ not applicable",
        }
        md.append("## Compliance (CRA, BSI TR-03183-2)\n")
        md.append(" · ".join(f"{labels.get(k, k)}: {v}" for k, v in summary.items() if v) + "\n")
        blocking = [c for c in compliance.get("controls", []) if c.get("status") in ("not_met", "gap")]
        for control in blocking:
            reason = next(
                (r["detail"] for r in control.get("checks", []) if r.get("result") == "fail"),
                " ".join(str(control.get("note", "")).split()),
            )
            md.append(f"- **{control['id']}** ({control['ref']}): {reason}")
        md.append("\nFull control-by-control report: `compliance-report.md` in this bundle.\n")

    md.append("## Gates\n")
    md.append("| Job | Result | Duration |\n| --- | --- | --- |")
    for job in jobs:
        conclusion = job.get("conclusion") or job.get("status", "?")
        icon = JOB_ICONS.get(conclusion, "⚪")
        md.append(f"| [{job.get('name', '?')}]({job.get('html_url', '')}) | {icon} {conclusion} | {_duration(job)} |")
    md.append("")
    md.append(
        "CodeQL and OpenSSF Scorecard run as separate workflows and report to GitHub code scanning; "
        "they are not part of this run.\n"
    )

    missing = [a for a in ("dependency-evidence", "image-evidence", "static-analysis-reports", "coverage-report")
               if a not in assembly.get("artifacts", [])]
    if missing:
        md.append(f"Artefacts not produced in this run: {', '.join(f'`{a}`' for a in missing)}.\n")

    inventory = []
    for path in sorted(p for p in evidence.rglob("*") if p.is_file()):
        rel = path.relative_to(evidence).as_posix()
        if rel.startswith("pipeline-report."):
            continue
        inventory.append({"path": rel, "sha256": sha256(path), "bytes": path.stat().st_size})
    md.append("## Evidence inventory\n")
    md.append(
        "Every file in this bundle (artefact `pipeline-evidence`), hashed. "
        "Retained 90 days; releases keep their own attested bundle.\n"
    )
    md.append("<details><summary>" + f"{len(inventory)} files" + "</summary>\n")
    md.append("| File | SHA-256 | Bytes |\n| --- | --- | ---: |")
    for item in inventory:
        md.append(f"| `{item['path']}` | `{item['sha256'][:16]}…` | {item['bytes']} |")
    md.append("\n</details>\n")

    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text("\n".join(md), encoding="utf-8")
    if out_json:
        out_json.write_text(
            json.dumps(
                {
                    "run": run,
                    "verdict": {"jobs": len(finished), "failed": [j.get("name") for j in failed]},
                    "figures": figures,
                    "compliance_summary": summary,
                    "jobs": [
                        {k: j.get(k) for k in ("name", "status", "conclusion", "started_at", "completed_at", "html_url")}
                        for j in jobs
                    ],
                    "evidence": inventory,
                },
                indent=2,
                ensure_ascii=False,
            )
            + "\n",
            encoding="utf-8",
        )
    print(f"pipeline-report: {verdict.replace('*', '')}")
    print(f"pipeline-report: wrote {out_md}" + (f" and {out_json}" if out_json else ""))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    p_assemble = sub.add_parser("assemble", help="map downloaded artefacts onto one evidence directory")
    p_assemble.add_argument("--artifacts", type=pathlib.Path, required=True)
    p_assemble.add_argument("--out", type=pathlib.Path, required=True)

    p_render = sub.add_parser("render", help="render the final report")
    p_render.add_argument("--evidence", type=pathlib.Path, required=True)
    p_render.add_argument("--jobs", type=pathlib.Path, required=True, help="JSON lines from the jobs API")
    p_render.add_argument("--out-md", type=pathlib.Path, required=True)
    p_render.add_argument("--out-json", type=pathlib.Path)

    args = parser.parse_args(argv)
    if args.command == "assemble":
        assemble(args.artifacts, args.out)
        return 0
    return render(args.evidence, args.jobs, args.out_md, args.out_json)


if __name__ == "__main__":
    sys.exit(main())
