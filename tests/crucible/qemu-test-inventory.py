"""Checks named QEMU Meson coverage against the reviewed thorough inventory.

Configuration and execution are checked separately. A configured inventory
does not establish that any test ran; execution additionally requires exactly
one successful or explicitly skipped result for every configured invocation.
The full-suite gate independently pins the permitted skip inventory.
"""

import argparse
import collections
import json
from pathlib import Path


class InventoryError(ValueError):
    """Reports malformed, missing, duplicate, or substituted test coverage."""


def unique_names(names, label):
    """Returns a name set only after checking nonempty, unambiguous rows."""
    if not names or any(not isinstance(name, str) or not name.strip() for name in names):
        raise InventoryError(f"{label} contains empty or invalid names")

    duplicates = sorted(name for name, count in collections.Counter(names).items() if count > 1)
    if duplicates:
        raise InventoryError(f"{label} contains duplicate names: {duplicates}")

    return set(names)


def compare_names(expected, actual, label):
    """Checks exact coverage, including substitutions that preserve the count."""
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    if missing or unexpected:
        raise InventoryError(f"{label} differs: missing={missing}, unexpected={unexpected}")


def configured_name(test):
    """Projects Meson's public name and suite fields to its displayed test name."""
    name = test.get("name")
    suites = test.get("suite")
    if not isinstance(name, str) or not name or not isinstance(suites, list) or not suites:
        raise InventoryError("Meson test has no name or suites")

    projects = []
    labels = []
    for suite in suites:
        if not isinstance(suite, str) or ":" not in suite:
            raise InventoryError(f"Malformed Meson suite: {suite!r}")
        project, label = suite.split(":", 1)
        if not project:
            raise InventoryError(f"Meson suite has no project: {suite!r}")
        projects.append(project)
        if label:
            labels.append(label)

    if len(set(projects)) != 1:
        raise InventoryError(f"Meson test crosses projects: {suites}")

    qualified_name = f"{projects[0]}:{name}"
    return f"{'+'.join(labels)} - {qualified_name}" if labels else qualified_name


def validate_configuration(expected, listed, tests):
    """Joins the reviewed names, actual thorough selection, and introspection."""
    expected_names = unique_names(expected, "Reviewed inventory")
    selected_names = unique_names(listed, "Thorough selection")
    if not isinstance(tests, list) or any(not isinstance(test, dict) for test in tests):
        raise InventoryError("Meson introspection is not a test list")

    configured_names = unique_names([configured_name(test) for test in tests], "Meson introspection")
    compare_names(expected_names, selected_names, "Thorough selection")
    compare_names(expected_names, configured_names, "Meson introspection")
    return len(expected_names)


def validate_results(expected, records):
    """Requires one completed result per reviewed invocation without failed rows."""
    expected_names = unique_names(expected, "Reviewed inventory")
    if any(not isinstance(record, dict) for record in records):
        raise InventoryError("Meson results contain a non-object row")

    observed_names = unique_names([record.get("name") for record in records], "Meson results")
    compare_names(expected_names, observed_names, "Meson results")
    for record in records:
        # Meson uses EXPECTEDFAIL for declared should-fail tests. A skipped
        # invocation still needs the separate full-suite skip-list check.
        if record.get("is_fail") is not False or record.get("result") not in {
            "OK", "SKIP", "EXPECTEDFAIL"
        }:
            raise InventoryError(f"Unsuccessful Meson result: {record.get('name')}")

    return len(expected_names)


def main():
    """Validates retained configure or execution artifacts without running tests."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["configured", "executed"])
    parser.add_argument("expected", type=Path)
    parser.add_argument("observed", type=Path)
    parser.add_argument("--introspection", type=Path)
    args = parser.parse_args()
    expected = args.expected.read_text(encoding="utf-8").splitlines()

    if args.mode == "configured":
        if args.introspection is None:
            parser.error("configured mode requires --introspection")
        count = validate_configuration(
            expected,
            args.observed.read_text(encoding="utf-8").splitlines(),
            json.loads(args.introspection.read_text(encoding="utf-8")),
        )
    else:
        records = [json.loads(line) for line in args.observed.read_text(encoding="utf-8").splitlines()]
        count = validate_results(expected, records)

    print(f"{args.mode}_tests={count}")


if __name__ == "__main__":
    try:
        main()
    except (InventoryError, OSError, json.JSONDecodeError) as error:
        raise SystemExit(str(error)) from error
