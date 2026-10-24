"""Checks PLAN-2 task references and ownership of mandatory requirement IDs.

The coverage table determines the documents in scope. Requirement declarations,
not incidental prose citations, establish identity; fenced examples and withdrawn
requirements do not create active obligations. Coverage assigns work and never
establishes implementation or conformance.
"""

import re
import sys
from pathlib import Path


DECLARATION = re.compile(r"^[ \t]*-[ \t]+\*\*\[([A-Z]+-[0-9]+)\]", re.MULTILINE)
TASK = re.compile(r"^- \[[ x]\] \*\*(T-[A-Z]+-[0-9]+)\*\*", re.MULTILINE)
IDENTIFIER = re.compile(r"\b[A-Z]+-[0-9]+\b")
RANGE = re.compile(r"\b([A-Z]+)-([0-9]+)\s+to\s+([A-Z]+)-([0-9]+)\b")


def without_fences(text: str) -> str:
    """Preserves line numbers while excluding Markdown fenced examples."""
    output = []
    fence = None
    for line in text.splitlines(keepends=True):
        marker = re.match(r"^\s*(`{3,}|~{3,})", line)
        if fence is None and marker:
            fence = marker[1]
        elif fence is not None and re.fullmatch(
            rf"\s*{re.escape(fence[0])}{{{len(fence)},}}\s*", line
        ):
            fence = None
            output.append("\n")
            continue
        output.append("\n" if fence is not None else line)
    if fence is not None:
        raise ValueError("PLAN-2: unterminated Markdown fence")
    return "".join(output)


def expand_ids(text: str) -> set[str]:
    """Expands explicit inclusive ranges and rejects reversed or mixed ranges."""
    identifiers = set(IDENTIFIER.findall(text))
    for prefix, first, last_prefix, last in RANGE.findall(text):
        if prefix != last_prefix or int(first) > int(last):
            raise ValueError(
                f"PLAN-2: invalid requirement range: {prefix}-{first} to {last_prefix}-{last}"
            )
        identifiers.update(
            f"{prefix}-{number}" for number in range(int(first), int(last) + 1)
        )
    return identifiers


def declarations(text: str) -> dict[str, str]:
    """Collects unique stable declarations and their following requirement text."""
    text = without_fences(text)
    matches = list(DECLARATION.finditer(text))
    result = {}
    for index, match in enumerate(matches):
        identifier = match[1]
        if identifier in result:
            raise ValueError(f"PLAN-2: repeated declaration: {identifier}")
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        result[identifier] = text[match.start():end]
    return result


def task_references(text: str) -> dict[str, set[str]]:
    """Reads each task's explicit satisfies clause without consuming later tasks."""
    text = without_fences(text)
    matches = list(TASK.finditer(text))
    result = {}
    for index, match in enumerate(matches):
        if match[1] in result:
            raise ValueError(f"PLAN-2: repeated task: {match[1]}")
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        clause = re.search(r"\bsatisfies\s+(.+?);", text[match.end():end], re.DOTALL)
        if clause is None:
            raise ValueError(f"PLAN-2: task has no satisfies clause: {match[1]}")
        # A future specification addition may deliberately have no current ID.
        result[match[1]] = expand_ids(clause[1])
    if not result:
        raise ValueError("PLAN-2: plan contains no tasks")
    return result


def covered_documents(root: Path, plan: str) -> list[Path]:
    """Resolves every numbered document in the plan's Coverage table exactly once."""
    coverage = plan.split("\n## Coverage\n")
    if len(coverage) != 2:
        raise ValueError("PLAN-2: expected exactly one Coverage section")
    rows = re.findall(
        r"^\| (integration )?([0-9]{2})\b[^|]*\|", coverage[1], re.MULTILINE
    )
    documents = []
    for integration, number in rows:
        directory = root / ("integration" if integration else "spec")
        matches = list(directory.glob(f"{number}-*.md"))
        if len(matches) != 1 or matches[0] in documents:
            raise ValueError(
                f"PLAN-2: missing or repeated coverage document: {directory.name}/{number}"
            )
        documents.append(matches[0])
    if not documents:
        raise ValueError("PLAN-2: coverage table contains no documents")
    return documents


def check(root: Path) -> tuple[int, int]:
    """Rejects undeclared task citations and mandatory declarations without a task."""
    plan = (root / "integration/05-implementation-plan.md").read_text()
    all_requirements = {}
    by_document = {}
    for document in sorted(root.glob("*/*.md")):
        requirements = declarations(document.read_text())
        repeated = set(requirements) & set(all_requirements)
        if repeated:
            raise ValueError(
                f"PLAN-2: declarations repeat across documents: {sorted(repeated)}"
            )
        all_requirements.update(requirements)
        by_document[document] = requirements

    tasks = task_references(plan)
    unknown = {
        task: sorted(ids - all_requirements.keys())
        for task, ids in tasks.items()
        if ids - all_requirements.keys()
    }
    if unknown:
        raise ValueError(f"PLAN-2: tasks cite undeclared requirement IDs: {unknown}")

    mandatory = set()
    for document in covered_documents(root, plan):
        for identifier, body in by_document[document].items():
            first_line = body.splitlines()[0]
            if "(withdrawn)" not in first_line and re.search(r"\bMUST\b", body):
                mandatory.add(identifier)

    cited = set().union(*tasks.values())
    missing = sorted(mandatory - cited)
    if missing:
        raise ValueError(f"PLAN-2: mandatory requirement IDs have no task: {missing}")
    return len(tasks), len(mandatory)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: plan_coverage.py RFC_ROOT")
    try:
        tasks, mandatory = check(Path(sys.argv[1]))
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from error
    print(
        f"PASS: {tasks} tasks cite declared IDs; "
        f"{mandatory} mandatory requirement IDs have task owners"
    )
