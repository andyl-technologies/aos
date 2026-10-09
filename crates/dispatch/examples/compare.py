"""Compares portable assignment documents through the machine JSON interface."""

import json
import pathlib
import subprocess
import sys


def main():
    executable = sys.argv[1] if len(sys.argv) > 1 else "dispatch"
    fixtures = pathlib.Path(__file__).with_name("fixtures")
    completed = subprocess.run(
        [
            executable,
            "compare",
            "--problem", str(fixtures / "packing.problem.json"),
            "--before", str(fixtures / "packing.before.json"),
            "--after", str(fixtures / "packing.after.json"),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    comparison = json.loads(completed.stdout)
    print(json.dumps(comparison, indent=2))


if __name__ == "__main__":
    main()
