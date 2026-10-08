#!/usr/bin/env python3
"""Enforce a licence policy over the Conan dependency graph.

Stage 4 of the pipeline (SCA) is usually discussed as CVE scanning, but the
other half of "third-party components and their known vulnerabilities and
licences" is the licence side, and it fails differently: a CVE is a bug you can
patch, a copyleft obligation you shipped unknowingly is a legal problem you
cannot patch retroactively.

Policy
------
Default-deny. A dependency passes only if every licence in its SPDX expression
is on the allowlist below. An unknown or missing licence is a *failure*, not a
pass - "the recipe did not say" is exactly the case worth catching early.

The allowlist is permissive-only, which is the right default for a service
distributed as a container image. Copyleft is not inherently disallowed in
general, it is disallowed *by this policy*, and the waiver flag exists for the
case where someone has actually read the terms and decided.

Usage
-----
    # resolve the graph and check it (what CI does)
    scripts/license_check.py

    # check a graph JSON produced earlier - no network, no Conan needed
    scripts/license_check.py --graph build/graph.json

    # accept one extra licence, or exempt one package, with a reason
    scripts/license_check.py --extra-allow MPL-2.0
    scripts/license_check.py --waive some-pkg/1.2.3

Scope
-----
Mirrors the SBOM: ``-o build_tests=False`` and host-context only, so the policy
covers what actually ships rather than what was needed to build it. A GPL test
framework never reaches a user; a GPL runtime dependency does.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

# Permissive licences, SPDX identifiers. Keep this list short and deliberate:
# every entry is a decision, not a convenience.
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

# Conan marks the consuming project itself with one of these. It is our own
# code, governed by LICENSE in the repo root, and is not a third-party
# component - checking it would just assert that we agree with ourselves.
OWN_RECIPE_KINDS = {"Consumer", "Cli", "Virtual", "Editable"}

# A licence string Conan could not determine. Treated as a violation.
UNKNOWN = "<unknown>"


class PolicyError(Exception):
    """The graph could not be obtained or understood."""


def resolve_graph(build_type: str) -> dict:
    """Ask Conan for the dependency graph as JSON.

    Uses the same options as scripts/sbom.sh so the licence policy and the SBOM
    describe the same set of components. If they diverged, the SBOM would list
    something the policy never looked at.
    """
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
    """Normalise Conan's ``license`` field to a single SPDX expression string.

    Recipes declare it as a string, or as a list/tuple when a package is
    multi-licensed. An empty value becomes UNKNOWN rather than an empty string
    so it cannot silently satisfy an "is it allowed" check.
    """
    if raw is None:
        return UNKNOWN
    if isinstance(raw, (list, tuple)):
        parts = [str(item).strip() for item in raw if str(item).strip()]
        if not parts:
            return UNKNOWN
        # A list means "all of these apply", which is SPDX AND.
        return " AND ".join(parts)
    text = str(raw).strip()
    return text or UNKNOWN


def expression_allowed(expression: str, allowed: set[str]) -> bool:
    """Evaluate a (simple) SPDX licence expression against the allowlist.

    Handles the forms that actually occur in ConanCenter recipes: a bare
    identifier, OR alternatives, AND combinations, and parenthesised groups of
    those. OR passes if any branch passes; AND needs every branch. Anything
    this cannot parse is reported as not allowed - failing closed is the whole
    point of a policy gate.
    """
    text = expression.strip()
    if not text or text == UNKNOWN:
        return False

    # Strip one layer of fully-enclosing parentheses: "(MIT OR Apache-2.0)".
    while text.startswith("(") and text.endswith(")") and _balanced(text[1:-1]):
        text = text[1:-1].strip()

    for operator, combine in (("OR", any), ("AND", all)):
        branches = _split_top_level(text, operator)
        if len(branches) > 1:
            return combine(expression_allowed(branch, allowed) for branch in branches)

    # A leaf. Trailing "+" means "or any later version" (GPL-2.0+); the base
    # identifier still decides, and "WITH <exception>" keeps the base licence.
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
    """Split on OPERATOR, ignoring occurrences inside parentheses."""
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
    """Extract (reference, licence expression) for every shipped dependency."""
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
        # Build-context nodes (cmake, ninja) are tooling: they run on the build
        # machine and never ship, which is why the SBOM drops them too.
        if node.get("context") == "build":
            continue
        # Test requirements are not distributed either.
        if node.get("test"):
            continue

        ref = str(node.get("ref") or node.get("name") or "<unnamed>")
        # Drop the recipe revision: "zlib/1.3#abc123" -> "zlib/1.3". The policy
        # is about the package, and the revision only adds noise to the report.
        components.append((ref.split("#", 1)[0], licence_text(node.get("license"))))

    # Deduplicate: a package can appear more than once in the graph.
    return sorted(set(components))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
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
        # Zero dependencies would mean the graph never resolved. This project has
        # two runtime requirements, so an empty result is a broken invocation -
        # and a gate that passes on an empty input is not a gate.
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

    # Written before the verdict is acted on: a failing run is exactly the one
    # whose report you want to keep, and the release evidence bundle should show
    # what the policy saw rather than only recording successes.
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
