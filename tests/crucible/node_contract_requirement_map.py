"""Checks RFC-0025 planning coverage without treating annotations as acceptance."""

import argparse
from collections import Counter
from dataclasses import dataclass
import json
from pathlib import Path
import re
import sys


HEADER = ("requirement", "chapter", "line", "phases", "tasks", "suites", "status")
STATUSES = {"planned", "in_progress", "implemented", "qualified"}
REQUIREMENT = re.compile(r"^(?:- )?\*\*\[(CN-[A-Z]+-[0-9]+)\]\*\*")


@dataclass(frozen=True)
class Location:
    """Identifies the defining normative anchor without normalizing its ID."""

    chapter: str
    line: int


def requirements_from_chapters(chapters: dict[str, str]) -> dict[str, Location]:
    """Indexes defining anchors, excluding fenced examples and ordinary links."""
    requirements = {}
    for chapter, contents in sorted(chapters.items()):
        fence = None
        for line_number, line in enumerate(contents.splitlines(), 1):
            marker = re.match(r"^ {0,3}(`{3,}|~{3,})(.*)$", line)
            if marker:
                delimiter = marker[1]
                if fence is None:
                    fence = delimiter
                elif (
                    delimiter[0] == fence[0]
                    and len(delimiter) >= len(fence)
                    and not marker[2].strip()
                ):
                    fence = None
                continue
            if fence is not None:
                continue

            anchor = REQUIREMENT.match(line)
            if anchor is None:
                if line.startswith(("**[CN-", "- **[CN-")):
                    raise ValueError(f"malformed requirement anchor: {chapter}:{line_number}")
                continue
            identifier = anchor[1]
            if identifier in requirements:
                raise ValueError(f"duplicate normative requirement: {identifier}")
            requirements[identifier] = Location(chapter, line_number)

    if not requirements:
        raise ValueError("RFC has no normative requirements")
    return requirements


def declared_assignments(plan: str, conformance: str) -> dict[str, set[str]]:
    """Reads assignment names from actual phase, task and suite declarations."""
    phases = set()
    for heading in re.findall(r"^## [0-9]+\. (.+)$", plan, re.MULTILINE):
        title = heading.split(" — ", 1)[0]
        phases.update(re.findall(r"\b(?:P|G)[0-9]+\b", title))
    tasks = re.findall(r"^\*\*(T-CN-[0-9]+):", plan, re.MULTILINE)
    suites = re.findall(r"^## [0-9.]+ Suite ([A-Z]):", conformance, re.MULTILINE)
    if len(tasks) != len(set(tasks)) or len(suites) != len(set(suites)):
        raise ValueError("duplicate task or suite declaration")
    assignments = {"phases": phases, "tasks": set(tasks), "suites": set(suites)}
    if any(not values for values in assignments.values()):
        raise ValueError("phase, task or suite declarations are absent")
    return assignments


def validate_map(
    chapters: dict[str, str], plan: str, mapping: str
) -> dict[str, object]:
    """Checks one exact coverage row per requirement and declared assignments.

    Status values remain unauthenticated planning annotations. This validator
    neither inspects runtime evidence nor qualifies an implementation or class.
    """
    requirements = requirements_from_chapters(chapters)
    conformance = chapters.get("08-conformance.md", "")
    assignments = declared_assignments(plan, conformance)
    lines = mapping.splitlines()
    if not lines or tuple(lines[0].split("\t")) != HEADER:
        raise ValueError("requirement map must have the exact seven-column TSV header")

    seen = set()
    statuses = Counter()
    for row_number, line in enumerate(lines[1:], 2):
        fields = line.split("\t")
        if len(fields) != len(HEADER):
            raise ValueError(f"wrong field count in requirement map row {row_number}")
        row = dict(zip(HEADER, fields))
        identifier = row["requirement"]
        if identifier in seen:
            raise ValueError(f"duplicate mapping: {identifier}")
        seen.add(identifier)
        location = requirements.get(identifier)
        if location is None:
            raise ValueError(f"unknown mapped requirement: {identifier}")
        if row["chapter"] != location.chapter or row["line"] != str(location.line):
            raise ValueError(f"stale defining location: {identifier}")

        for column, declared in assignments.items():
            values = row[column].split(",")
            if len(values) != len(set(values)) or any(value not in declared for value in values):
                raise ValueError(f"unknown, empty or duplicate {column}: {identifier}")
        if row["status"] not in STATUSES:
            raise ValueError(f"unknown planning status: {identifier}")
        statuses[row["status"]] += 1

    missing = requirements.keys() - seen
    if missing:
        raise ValueError("unmapped normative requirements: " + ", ".join(sorted(missing)))
    return {
        "schema": "crucible-node-contract.requirement-index/1",
        "scope": "documentation consistency; no implementation acceptance",
        "requirements": len(requirements),
        "planning_annotations": dict(sorted(statuses.items())),
    }


def main() -> int:
    """Validates the selected source files and writes only consistency evidence."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rfc-dir", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--map", type=Path, required=True, dest="mapping")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    try:
        chapters = {
            path.relative_to(args.rfc_dir).as_posix(): path.read_text(encoding="utf-8")
            for path in args.rfc_dir.rglob("*.md")
        }
        report = validate_map(
            chapters,
            args.plan.read_text(encoding="utf-8"),
            args.mapping.read_text(encoding="utf-8"),
        )
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError) as error:
        print(f"RFC-0025 requirement map: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
