#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

ALLOWED: set[str] = {
    "0BSD",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "BSL-1.0",
    "CC0-1.0",
    "ISC",
    "MIT",
    "MIT-0",
    "Unlicense",
    "Zlib",
    "libpng-2.0",
}

OWN_RECIPE_KINDS = {"Consumer", "Cli", "Virtual", "Editable"}

UNKNOWN = "<unknown>"


class PolicyError(Exception):
    pass


def resolve_graph(build_type: str) -> dict:
    command = [
        "conan",
        "graph",
        "info",
        str(REPO_ROOT),
        "--format=json",
        "-s",
        f"build_type={build_type}",
        "-o",
        "&:build_tests=False",
    ]
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, check=True, cwd=REPO_ROOT
        )
    except FileNotFoundError as exc:
        raise PolicyError('conan not found. pip install "conan>=2.0"') from exc
    except subprocess.CalledProcessError as exc:
        raise PolicyError(
            f"conan graph info failed (exit {exc.returncode}):\n{exc.stderr.strip()}"
        ) from exc

    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise PolicyError(f"conan produced output that is not JSON: {exc}") from exc


def load_graph(path: pathlib.Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PolicyError(f"graph file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise PolicyError(f"{path} is not valid JSON: {exc}") from exc


def licence_text(raw: object) -> str:
    if raw is None:
        return UNKNOWN
    if isinstance(raw, (list, tuple)):
        parts = [str(item).strip() for item in raw if str(item).strip()]
        if not parts:
            return UNKNOWN
        return " AND ".join(parts)
    text = str(raw).strip()
    return text or UNKNOWN


def expression_allowed(expression: str, allowed: set[str]) -> bool:
    text = expression.strip()
    if not text or text == UNKNOWN:
        return False

    while text.startswith("(") and text.endswith(")") and _balanced(text[1:-1]):
        text = text[1:-1].strip()

    for operator, combine in (("OR", any), ("AND", all)):
        branches = _split_top_level(text, operator)
        if len(branches) > 1:
            return combine(expression_allowed(branch, allowed) for branch in branches)

    leaf = re.split(r"\s+WITH\s+", text, maxsplit=1)[0].strip().rstrip("+")
    return leaf in allowed


def _balanced(text: str) -> bool:
    depth = 0
    for char in text:
        depth += (char == "(") - (char == ")")
        if depth < 0:
            return False
    return depth == 0


def _split_top_level(text: str, operator: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for token in re.split(r"(\s+|\(|\))", text):
        if token == "(":
            depth += 1
        elif token == ")":
            depth -= 1
        if depth == 0 and token.strip().upper() == operator:
            parts.append("".join(current).strip())
            current = []
            continue
        current.append(token)
    parts.append("".join(current).strip())
    return [part for part in parts if part]


def collect_components(graph: dict) -> list[tuple[str, str]]:
    nodes = graph.get("graph", {}).get("nodes")
    if not isinstance(nodes, dict):
        raise PolicyError(
            "unexpected graph shape: expected graph.nodes to be an object. "
            "Was this produced by 'conan graph info --format=json'?"
        )

    components: list[tuple[str, str]] = []
    for node in nodes.values():
        if not isinstance(node, dict):
            continue
        if node.get("recipe") in OWN_RECIPE_KINDS:
            continue
        if node.get("context") == "build":
            continue
        if node.get("test"):
            continue

        ref = str(node.get("ref") or node.get("name") or "<unnamed>")
        components.append((ref.split("#", 1)[0], licence_text(node.get("license"))))

    return sorted(set(components))


def main() -> int:
    parser = argparse.ArgumentParser(description="Enforce a licence policy over the Conan dependency graph.")
    parser.add_argument(
        "--graph",
        type=pathlib.Path,
        help="read a 'conan graph info --format=json' file instead of running Conan",
    )
    parser.add_argument(
        "--build-type", default="Release", help="Conan build_type (default: Release)"
    )
    parser.add_argument(
        "--extra-allow",
        action="append",
        default=[],
        metavar="SPDX",
        help="additionally allow this SPDX identifier (repeatable)",
    )
    parser.add_argument(
        "--waive",
        action="append",
        default=[],
        metavar="REF",
        help="exempt a package reference, e.g. 'some-pkg/1.2.3' (repeatable)",
    )
    parser.add_argument(
        "--json-out",
        type=pathlib.Path,
        help="also write the findings as JSON, for the release evidence bundle",
    )
    args = parser.parse_args()

    allowed = ALLOWED | {item.strip() for item in args.extra_allow if item.strip()}
    waived = {item.strip() for item in args.waive if item.strip()}

    try:
        graph = load_graph(args.graph) if args.graph else resolve_graph(args.build_type)
        components = collect_components(graph)
    except PolicyError as exc:
        print(f"license-check: {exc}", file=sys.stderr)
        return 2

    if not components:
        print(
            "license-check: the graph contains no shipped dependencies, which "
            "cannot be right - refusing to report success.",
            file=sys.stderr,
        )
        return 2

    violations: list[tuple[str, str]] = []
    rows: list[tuple[str, str, str]] = []
    for ref, licence in components:
        if ref in waived or ref.split("/", 1)[0] in waived:
            verdict = "WAIVED"
        elif expression_allowed(licence, allowed):
            verdict = "ok"
        else:
            verdict = "DENIED"
            violations.append((ref, licence))
        rows.append((ref, licence, verdict))

    width = max(len(ref) for ref, _, _ in rows)
    print(f"license-check: {len(rows)} shipped component(s)\n")
    for ref, licence, verdict in rows:
        marker = " " if verdict == "ok" else ">"
        print(f"{marker} {ref:<{width}}  {licence:<24} {verdict}")

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(
            json.dumps(
                {
                    "policy": {"allowed": sorted(allowed), "waived": sorted(waived)},
                    "components": [
                        {"ref": ref, "license": licence, "verdict": verdict}
                        for ref, licence, verdict in rows
                    ],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"\nlicense-check: wrote {args.json_out}")

    if violations:
        print("\nLicence policy violations:")
        for ref, licence in violations:
            reason = (
                "no licence declared in the recipe"
                if licence == UNKNOWN
                else f"'{licence}' is not on the allowlist"
            )
            print(f"  {ref}: {reason}")
        print(
            "\nResolve by replacing the dependency, extending the policy "
            "(--extra-allow / the ALLOWED set in this script), or recording a "
            "reviewed exemption (--waive). Do not do the last one silently."
        )
        return 1

    print("\nlicense-check: all shipped components satisfy the policy.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
