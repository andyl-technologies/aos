"""Checks exported toolchain interpreters and GCC program selection.

The JSON input maps tier names to maps of tool names and output paths. Build
dependencies and strings in documentation are deliberately not executable
dependencies. Missing outputs or inspection failures never count as a pass.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess


def inside(path, roots):
    """Resolves aliases before testing membership in a tier's output roots."""
    resolved = Path(path).resolve(strict=True)
    return any(resolved == root or root in resolved.parents for root in roots)


def inspect_path(path, root, roots):
    """Checks executable aliases and shebangs, leaving metadata uninterpreted."""
    executable_tree = path.relative_to(root).parts[0] in {
        "bin", "sbin", "lib", "libexec",
    }
    if path.is_symlink() and not path.exists() and executable_tree:
        return ["dangling executable or library alias"]

    executable_file = path.is_file() and os.access(path, os.X_OK)
    executable_alias = executable_file or (path.is_dir() and executable_tree)
    reasons = []
    if path.is_symlink() and executable_alias and not inside(path, roots):
        reasons.append("symlink leaves exported tier outputs")
    if not executable_file:
        return reasons

    with path.open("rb") as source:
        prefix = source.read(4096)
    if not prefix.startswith(b"#!"):
        return reasons

    words = prefix.splitlines()[0][2:].decode("utf-8").split()
    if not words or not Path(words[0]).is_absolute():
        reasons.append("missing or relative interpreter")
    elif not inside(words[0], roots):
        reasons.append(f"interpreter leaves exported tier: {words[0]}")
    elif Path(words[0]).resolve(strict=True).name == "env":
        reasons.append("env shebang defers interpreter selection to ambient PATH")
    return reasons


def inspect_tier(name, packages):
    """Returns violations at the public export boundary of one tier."""
    violations = []

    def reject(path, reason):
        violations.append({"tier": name, "path": str(path), "reason": reason})

    roots = []
    for path in sorted(set(packages.values())):
        try:
            roots.append(Path(path).resolve(strict=True))
        except OSError as error:
            reject(path, f"unavailable output: {error}")

    # Do not follow directory symlinks recursively: GCC links a whole target
    # tree, which can contain cycles. Every exported root is scanned directly;
    # external executable directory aliases must still stay inside this tier.
    for root in roots:
        entries = os.walk(root, onerror=lambda error: reject(root, str(error)))
        for directory, directories, filenames in entries:
            for filename in directories + filenames:
                path = Path(directory) / filename
                try:
                    for reason in inspect_path(path, root, roots):
                        reject(path, reason)
                except (OSError, UnicodeError, RuntimeError) as error:
                    reject(path, f"cannot inspect executable dependency: {error}")

    # A modern-looking wrapper can still select a historical assembler via
    # GCC specs or -B. Ask the actual exported driver, with no ambient tools.
    if "gcc" not in packages or "binutils" not in packages:
        reject(name, "tier must declare gcc and binutils outputs")
        return violations

    gcc = Path(packages["gcc"]) / "bin/gcc"
    for program in ("as", "ld"):
        expected = Path(packages["binutils"]) / "bin" / program
        try:
            result = subprocess.run(
                [str(gcc), f"-print-prog-name={program}"],
                env={"PATH": "/nonexistent", "LC_ALL": "C"},
                capture_output=True,
                text=True,
                timeout=30,
                check=True,
            )
            selected = Path(result.stdout.strip())
            matches = (
                selected.is_absolute()
                and selected.resolve(strict=True) == expected.resolve(strict=True)
            )
            if not matches:
                reject(gcc, f"{program} selects {selected}; expected {expected}")
        except (OSError, RuntimeError, subprocess.SubprocessError) as error:
            reject(gcc, f"cannot establish {program} selection: {error}")

    return violations


def main():
    """Writes a machine-readable report and fails on any violation."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inventory", type=Path)
    parser.add_argument("report", type=Path)
    arguments = parser.parse_args()
    inventory = json.loads(arguments.inventory.read_text())
    if not inventory:
        parser.error("the tier inventory must not be empty")

    violations = []
    for name, packages in sorted(inventory.items()):
        violations.extend(inspect_tier(name, packages))
    report = {"schema_version": 1, "tiers": sorted(inventory), "violations": violations}
    arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    for violation in violations:
        print(f"{violation['tier']}: {violation['path']}: {violation['reason']}")
    return bool(violations)


if __name__ == "__main__":
    raise SystemExit(main())
