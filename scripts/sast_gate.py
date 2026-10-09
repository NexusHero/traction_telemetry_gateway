#!/usr/bin/env python3
"""Turn clang-tidy / cppcheck reporting into a gate, via a frozen baseline.

SECURITY.md describes the rollout this implements:

  1. Run the tool without a gate; let it collect a baseline.
  2. Freeze the baseline. Treat only *new* findings as blocking.
  3. Tighten the gate once the baseline is clean.

Step 2 is the part that needs code. A gate that fails on every pre-existing
finding gets switched off within two weeks; a gate that fails only on findings
a change actually introduced survives, and the baseline shrinks over time
because lowering it is the easy direction.

Usage
-----
    # fail if the reports contain findings the baseline does not account for
    sast_gate.py check --baseline .sast-baseline.txt clang-tidy.txt cppcheck.txt

    # record the current findings as the accepted baseline
    sast_gate.py update --baseline .sast-baseline.txt clang-tidy.txt cppcheck.txt

Baseline format
---------------
One record per line, "<count>\t<file>\t<check>", sorted. Deliberately not JSON:
it is reviewed in pull requests, and a one-line diff should mean one changed
finding.

Why no line numbers
-------------------
A baseline keyed on line numbers invalidates itself on the next edit above the
finding, which trains people to regenerate it blindly - and a blindly
regenerated baseline accepts whatever is in the tree, gate included. Keying on
(file, check) with a count is stable under edits while still catching a *new*
instance of an already-known check in the same file.
"""

from __future__ import annotations

import argparse
import collections
import os
import pathlib
import re
import sys

# clang-tidy:  /abs/path/src/parser.cpp:42:17: warning: message [bugprone-foo]
# cppcheck:    src/parser.cpp:42:17: warning: message [uninitvar]
#              (CI pins --template to this shape, see ci.yml)
FINDING_RE = re.compile(
    r"""^
    # Path, repo-relative or absolute. The optional drive-letter prefix matters:
    # without it, "C:/src/parser.cpp:42:1" parses as file "C" and the whole
    # finding is silently dropped on Windows, where developers run the hook.
    (?P<file>(?:[A-Za-z]:)?[^\s:][^:]*)
    :(?P<line>\d+)
    :(?P<col>\d+)
    :\s*
    (?P<severity>warning|error|style|performance|portability|information)
    :\s*
    (?P<message>.*?)
    \s*\[(?P<check>[A-Za-z0-9_.,\-]+)\]
    \s*$""",
    re.VERBOSE,
)

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

# cppcheck reports these against itself, not against the code under analysis.
# Letting them into the baseline would make the gate depend on how cppcheck was
# invoked rather than on what the code says.
SELF_DIAGNOSTICS = {"missingInclude", "missingIncludeSystem", "checkersReport"}


class MissingReport(Exception):
    """An analyser report named on the command line does not exist."""


def normalise_path(raw: str) -> str:
    """Make a reported path repo-relative with forward slashes.

    clang-tidy reports absolute paths, cppcheck relative ones, and the absolute
    prefix differs between a CI runner and a developer's machine. Without this,
    a baseline recorded in one place is worthless in the other.
    """
    try:
        resolved = pathlib.Path(raw).resolve()
        return resolved.relative_to(REPO_ROOT).as_posix()
    except (ValueError, OSError):
        # Outside the repo (a system header, say) - keep it as-is, but still
        # normalise separators so the key is platform-stable.
        return raw.replace(os.sep, "/")


def parse_reports(paths: list[str]) -> tuple[collections.Counter, int]:
    """Aggregate findings from tool output into {(file, check): count}.

    Also returns the number of unique findings, so the caller can tell "clean
    run" apart from "the report is empty because the tool never ran" - the
    second is a broken pipeline, not a passing gate.
    """
    # Dedupe on the exact location first: clang-tidy re-reports a finding in a
    # header once per translation unit that includes it, which would otherwise
    # inflate the count and make the gate depend on how many .cpp files exist.
    seen: set[tuple[str, str, str, str]] = set()

    for path in paths:
        try:
            text = pathlib.Path(path).read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError as exc:
            # Hard error, not a skip. A report that does not exist produces zero
            # findings, which would sail through the gate and report success for
            # an analyser that never ran - the one failure mode a gate must
            # never have.
            raise MissingReport(f"report not found: {path}") from exc
        for raw_line in text.splitlines():
            match = FINDING_RE.match(raw_line.strip())
            if not match:
                continue
            check = match.group("check")
            if check in SELF_DIAGNOSTICS:
                continue
            seen.add(
                (
                    normalise_path(match.group("file")),
                    match.group("line"),
                    match.group("col"),
                    check,
                )
            )

    counter: collections.Counter = collections.Counter()
    for file_name, _line, _col, check in seen:
        counter[(file_name, check)] += 1
    return counter, len(seen)


class MalformedBaseline(Exception):
    """The baseline file could not be parsed.

    Raised rather than returned so a corrupt baseline can never be mistaken for
    an empty one - an empty baseline means "nothing is accepted", which is a
    strict gate, but a *silently* empty one hides the fact that the recorded
    exemptions were lost.
    """


def read_baseline(path: pathlib.Path) -> collections.Counter:
    counter: collections.Counter = collections.Counter()
    if not path.exists():
        return counter
    for number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != 3:
            raise MalformedBaseline(f"{path}:{number}: expected 3 tab-separated fields")
        count, file_name, check = parts
        try:
            counter[(file_name, check)] += int(count)
        except ValueError as exc:
            raise MalformedBaseline(f"{path}:{number}: {count!r} is not a count") from exc
    return counter


def write_baseline(path: pathlib.Path, findings: collections.Counter) -> None:
    header = [
        "# clang-tidy / cppcheck findings accepted as pre-existing.",
        "# Format: <count><TAB><file><TAB><check>",
        "#",
        "# Regenerate from CI's uploaded reports with:",
        "#   scripts/sast_gate.py update clang-tidy.txt cppcheck.txt",
        "#",
        "# Lowering a count is always safe and always welcome. Raising one needs a",
        "# reason in the pull request that does it.",
    ]
    body = [
        f"{count}\t{file_name}\t{check}"
        for (file_name, check), count in sorted(findings.items())
    ]
    path.write_text("\n".join(header + body) + "\n", encoding="utf-8")


def cmd_check(args: argparse.Namespace) -> int:
    baseline = read_baseline(pathlib.Path(args.baseline))
    current, unique = parse_reports(args.reports)

    regressions = [
        (key, baseline.get(key, 0), count)
        for key, count in sorted(current.items())
        if count > baseline.get(key, 0)
    ]
    improvements = [
        (key, allowed, current.get(key, 0))
        for key, allowed in sorted(baseline.items())
        if current.get(key, 0) < allowed
    ]

    print(f"sast-gate: {unique} finding(s) in {len(current)} (file, check) group(s)")
    print(f"sast-gate: baseline accounts for {sum(baseline.values())} finding(s)")

    if improvements:
        print("\nImproved since the baseline was recorded (consider lowering it):")
        for (file_name, check), allowed, count in improvements:
            print(f"  {file_name}: {check}: {allowed} -> {count}")

    if regressions:
        print("\nNew findings - these block the build:")
        for (file_name, check), allowed, count in regressions:
            print(f"  {file_name}: {check}: baseline {allowed}, now {count}")
        print(
            "\nFix them, or - if they are genuinely acceptable - record them with:\n"
            f"  scripts/sast_gate.py update {' '.join(args.reports)}"
        )
        return 1

    print("\nsast-gate: no new findings.")
    return 0


def cmd_update(args: argparse.Namespace) -> int:
    current, unique = parse_reports(args.reports)
    write_baseline(pathlib.Path(args.baseline), current)
    print(
        f"sast-gate: recorded {unique} finding(s) in {len(current)} group(s) "
        f"to {args.baseline}"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    for name, handler, help_text in (
        ("check", cmd_check, "fail on findings the baseline does not account for"),
        ("update", cmd_update, "record current findings as the baseline"),
    ):
        sub_parser = sub.add_parser(name, help=help_text)
        sub_parser.add_argument(
            "--baseline",
            default=str(REPO_ROOT / ".sast-baseline.txt"),
            help="baseline file (default: .sast-baseline.txt in the repo root)",
        )
        sub_parser.add_argument(
            "reports", nargs="+", help="clang-tidy / cppcheck output files"
        )
        sub_parser.set_defaults(func=handler)

    args = parser.parse_args()
    try:
        return args.func(args)
    except MalformedBaseline as exc:
        print(f"sast-gate: {exc}", file=sys.stderr)
        print(
            "sast-gate: refusing to run with an unreadable baseline - fix the file "
            "or regenerate it with 'sast_gate.py update'.",
            file=sys.stderr,
        )
        return 2
    except MissingReport as exc:
        print(f"sast-gate: {exc}", file=sys.stderr)
        print(
            "sast-gate: refusing to pass a gate on a report that does not exist - "
            "check that the analyser step ran and wrote its output.",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())
