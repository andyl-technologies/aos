"""Requires the reviewed public format corpus to compile and execute in full.

The catalog names coverage obligations, not a minimum passing-test count.
Changes to it require review together with the corresponding format properties.
"""

import argparse
from collections import Counter
from pathlib import Path
import re


def catalog(path):
    """Reads the nonempty, sorted, unique list of required test names."""
    names = path.read_text(encoding="utf-8").splitlines()
    if not names or names != sorted(set(names)):
        raise ValueError("format property catalog must be nonempty, sorted and unique")
    if any(not re.fullmatch(r"[a-z0-9_]+::[a-z0-9_]+", name) for name in names):
        raise ValueError("format property catalog contains an invalid test name")
    return names


def validate_inventory(output, names):
    """Requires precisely the reviewed compiled integration-test inventory."""
    observed = re.findall(r"^(.+): test$", output, re.MULTILINE)
    if Counter(observed) != Counter(names):
        raise ValueError("compiled format property inventory differs from the catalog")
    summary = f"{len(names)} tests, 0 benchmarks"
    if output.splitlines().count(summary) != 1:
        raise ValueError("compiled format property inventory has no exact summary")


def validate_execution(output, names):
    """Requires every reviewed property to pass once without skips or filtering."""
    observed = re.findall(r"^test (\S+) \.\.\. ok$", output, re.MULTILINE)
    if Counter(observed) != Counter(names):
        raise ValueError("format property execution omitted or repeated a required case")
    summary = (f"test result: ok. {len(names)} passed; 0 failed; 0 ignored; "
               "0 measured; 0 filtered out;")
    if output.count(summary) != 1:
        raise ValueError("format property execution must have no failures or skips")


def main():
    """Checks the compiled inventory or actual execution against the catalog."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("catalog", type=Path)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--inventory", type=Path)
    modes.add_argument("--execution", type=Path)
    arguments = parser.parse_args()

    names = catalog(arguments.catalog)
    path = arguments.inventory or arguments.execution
    output = path.read_text(encoding="utf-8")
    print(output, end="" if output.endswith("\n") else "\n")
    if arguments.inventory:
        validate_inventory(output, names)
    else:
        validate_execution(output, names)
    print(f"PASS: all {len(names)} reviewed public format properties are present")


if __name__ == "__main__":
    main()
