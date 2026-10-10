#!/usr/bin/env python3

from __future__ import annotations

import argparse
import collections
import os
import pathlib
import re
import sys

FINDING_RE = re.compile(
    r"""^
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

SELF_DIAGNOSTICS = {"missingInclude", "missingIncludeSystem", "checkersReport"}


class MissingReport(Exception):
    pass


def normalise_path(raw: str) -> str:
    try:
        resolved = pathlib.Path(raw).resolve()
        return resolved.relative_to(REPO_ROOT).as_posix()
    except (ValueError, OSError):
        return raw.replace(os.sep, "/")


def parse_reports(paths: list[str]) -> tuple[collections.Counter, int]:
    seen: set[tuple[str, str, str, str]] = set()

    for path in paths:
        try:
            text = pathlib.Path(path).read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError as exc:
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
    pass


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
    parser = argparse.ArgumentParser(description="Turn clang-tidy / cppcheck reporting into a gate, via a frozen baseline.")
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
