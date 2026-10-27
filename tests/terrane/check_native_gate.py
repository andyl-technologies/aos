"""Requires named native conformance tests to exist and execute successfully."""

import argparse
import json
import pathlib
import re


def check_output(mode, output, required):
    """Checks discovery separately from successful, non-ignored execution."""
    if not required or len(required) != len(set(required)):
        raise ValueError("gate must require a nonempty, unique test set")

    if mode == "inventory":
        observed = set(re.findall(r"^(.+): test$", output, re.MULTILINE))
    else:
        observed = set(re.findall(r"^test (.+) \.\.\. ok$", output, re.MULTILINE))
        summary = re.search(
            r"test result: ok\. ([1-9][0-9]*) passed; 0 failed; 0 ignored;",
            output,
        )
        if summary is None:
            raise ValueError("native suite did not execute passing, non-ignored tests")

    missing = sorted(set(required) - observed)
    if missing:
        raise ValueError("required native tests missing or unqualified: " + ", ".join(missing))


def main():
    """Validates one Cargo discovery or execution report against exact names."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("inventory", "execution"))
    parser.add_argument("report", type=pathlib.Path)
    parser.add_argument("required", help="JSON array of exact qualified test names")
    args = parser.parse_args()

    required = json.loads(args.required)
    if not isinstance(required, list) or any(not isinstance(name, str) for name in required):
        parser.error("required tests must be a JSON array of strings")

    output = args.report.read_text()
    try:
        check_output(args.mode, output, required)
    except ValueError as error:
        parser.exit(1, f"{error}\n")

    print(output, end="")


if __name__ == "__main__":
    main()
