"""Checks the specification gate registry and its AOS check mapping.

TEST-16 requires a unique registered row for each normative gate citation;
PKG-7 and PKG-11 require the same names to be addressable as AOS checks.
Pending checks remain addressable and fail when built. Registration does
not claim that their requirements have been implemented.
"""

import collections
import json
import re
import sys
from pathlib import Path


GATE_NAME = re.compile(r"gate:([a-z0-9]+(?:-[a-z0-9]+)*)(?![a-z0-9*-])")
REGISTRY_ROW = re.compile(
    r"\| `gate:([a-z0-9-]+)` \| ([0-9]+) \| (.+) \|"
)
REQUIREMENT_ID = re.compile(r"\b[A-Z]+-[0-9]+\b")
REQUIREMENT_DECLARATION = re.compile(
    r"^\s*-\s+\*\*\[([A-Z]+-[0-9]+)\]", re.MULTILINE
)


def check_registry(spec: Path, registry: Path, check_names: Path) -> None:
    """Rejects missing, duplicate, stale, or unowned gate mappings."""
    rows = []
    for line in (spec / "36-testing-and-conformance.md").read_text().splitlines():
        match = REGISTRY_ROW.fullmatch(line)
        if match:
            rows.append(
                {"name": match[1], "owner": match[2], "requirements": match[3]}
            )

    counts = collections.Counter(row["name"] for row in rows)
    duplicates = sorted(name for name, count in counts.items() if count != 1)
    if duplicates:
        raise ValueError(f"TEST-16: duplicate registry rows: {duplicates}")

    cited = set()
    for number in range(1, 39):
        matches = list(spec.glob(f"{number:02d}-*.md"))
        if len(matches) != 1:
            raise ValueError(f"TEST-16: expected one specification file {number}")
        cited.update(GATE_NAME.findall(matches[0].read_text()))

    # The informative surveys carry no conformance obligations (CONV-2).
    for reference in (spec / "reference").iterdir():
        if reference.name not in {"prior-art.md", "comparisons.md"}:
            cited.update(GATE_NAME.findall(reference.read_text()))

    registered = set(counts)
    missing = sorted(cited - registered)
    if missing:
        raise ValueError(f"TEST-16: unregistered normative gates: {missing}")

    expected = json.loads(registry.read_text())
    if sorted(expected, key=lambda row: row["name"]) != sorted(
        rows, key=lambda row: row["name"]
    ):
        raise ValueError("PKG-7: AOS registry differs from specification registry")

    actual = json.loads(check_names.read_text())
    if set(actual) != registered or len(actual) != len(registered):
        raise ValueError("PKG-7: AOS check names differ from specification registry")

    # Ownership may cross specification files. Declarations, rather than
    # incidental references in prose, establish the set of stable IDs.
    declared = set()
    for document in spec.glob("[0-9][0-9]-*.md"):
        declared.update(REQUIREMENT_DECLARATION.findall(document.read_text()))

    unowned = sorted(
        row["name"]
        for row in rows
        if not REQUIREMENT_ID.search(row["requirements"])
    )
    if unowned:
        raise ValueError(f"TEST-16: registry rows name no requirement ID: {unowned}")

    unknown = {}
    for row in rows:
        referenced = set(REQUIREMENT_ID.findall(row["requirements"]))
        missing = referenced - declared
        if missing:
            unknown[row["name"]] = sorted(missing)

    if unknown:
        raise ValueError(f"TEST-16: registry rows reference undeclared IDs: {unknown}")

    print(f"PASS: {len(rows)} unique specification gates map to AOS checks")


def main() -> None:
    """Runs the registry check with a diagnostic and nonzero failure status."""
    if len(sys.argv) != 4:
        raise SystemExit("usage: gate_registry.py SPEC REGISTRY CHECK_NAMES")

    try:
        check_registry(*(Path(argument) for argument in sys.argv[1:]))
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from error


if __name__ == "__main__":
    main()
