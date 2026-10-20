"""Checks settlement with isolated component symbols and genuine QOM support.

The configured Meson objects supply QOM and its support providers. The literal
component remains in its own namespace, including its deterministic event and
lock controls, so linked support cannot accidentally use a fixture provider.
"""

import argparse
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys


def unique(items, description):
    if len(items) != 1:
        raise ValueError(f"expected exactly one {description}")
    return items[0]


def configured_source(entry):
    """Normalizes compile-database paths in their original build coordinates."""
    source = Path(entry["file"])
    if not source.is_absolute():
        source = Path(entry["directory"]) / source
    return os.path.normpath(source)


def configured_support(build_root, environment):
    """Resolves the actual configured QOM objects and unit link dependencies."""
    commands = json.loads((build_root / "compile_commands.json").read_text())
    targets = json.loads((build_root / "meson-info/intro-targets.json").read_text())
    compiler = environment["CC"]
    objects = []
    for name in ("event-loop-base", "qom"):
        target = unique([item for item in targets if item["name"] == name], name)
        sources = [
            source
            for group in target["target_sources"]
            for source in group.get("sources", [])
        ]
        if not sources:
            raise ValueError(f"configured {name} has no provider sources")

        for source in sources:
            entry = unique(
                [item for item in commands if configured_source(item) == source],
                f"configured compile command for {source}",
            )
            command = shlex.split(entry["command"])
            if command[0] != compiler:
                raise ValueError("QOM support uses a different configured compiler")
            output = Path(command[command.index("-o") + 1])
            output = output if output.is_absolute() else build_root / output
            if not output.is_file():
                raise ValueError(f"configured provider object is absent: {output}")
            objects.append(str(output))

    unit = unique(
        [item for item in targets if item["name"] == "check-qom-interface"],
        "configured QOM interface unit",
    )
    link = unique(
        [group for group in unit["target_sources"] if "linker" in group],
        "configured QOM interface linker",
    )
    if link["linker"][0] != compiler:
        raise ValueError("QOM unit uses a different configured linker driver")

    parameters = link["parameters"]
    library_directories = sorted({
        str(Path(argument).parent)
        for argument in parameters
        if Path(argument).is_absolute() and ".so" in Path(argument).name
    })
    flags = objects + parameters + shlex.split(environment["LDFLAGS"])
    if library_directories:
        flags.append("-Wl,-rpath," + ":".join(library_directories))
    return shlex.join(flags)


def check_component_symbols(output, build_root, environment, nm):
    """Rejects component definitions in the real provider's symbol namespace."""
    recipe = json.loads((output / "compile-command.json").read_text())
    command = recipe["argv"]
    source = str(output / "settle-prepark.c")
    if command[0] != environment["CC"]:
        raise ValueError("component compiler differs from configured support")
    source_index = command.index(source)
    component = output / "component.o"
    compile_command = command[:source_index] + ["-c", source, "-o", str(component)]
    subprocess.run(compile_command, cwd=build_root, env=environment, check=True)
    symbols = subprocess.run(
        [str(nm), "--defined-only", "--extern-only", str(component)],
        capture_output=True, text=True, check=True,
    ).stdout
    (output / "component-symbols.txt").write_text(symbols)
    names = [line.split()[-1] for line in symbols.splitlines() if line.strip()]
    if len(names) != 50 or names.count("main") != 1 or any(
        name != "main" and not name.startswith("settle_prepark_component_")
        for name in names
    ):
        raise ValueError("settlement component leaks a provider symbol")


def check_negative_control(command, output, build_root, environment):
    """Requires the exact guard deletion to fail at its settlement assertion."""
    negative = output / "negative"
    if negative.exists():
        raise ValueError("settlement mutation requires a fresh output directory")
    mutation_command = command.copy()
    mutation_command[mutation_command.index("--output-dir") + 1] = str(negative)
    mutation_command += ["--negative-control", "settle-scan"]
    generated = subprocess.run(
        mutation_command, cwd=build_root, env=environment,
        capture_output=True, text=True,
    )
    negative.mkdir(exist_ok=True)
    (negative / "driver.stdout").write_text(generated.stdout)
    (negative / "driver.stderr").write_text(generated.stderr)
    if generated.returncode != 1:
        raise ValueError("settlement mutation did not report its expected refusal")

    original = (output / "settle-prepark.c").read_text()
    guard = "qemu_plugin_time_advance_settle_is_pending() ||\n        "
    if original.count(guard) != 1 or (
        negative / "settle-prepark.c"
    ).read_text() != original.replace(guard, "", 1):
        raise ValueError("settlement mutation changed more than its exact guard")

    refused = subprocess.run(
        [str(negative / "settle-prepark")], cwd=negative,
        capture_output=True, text=True,
    )
    (negative / "native.stdout").write_text(refused.stdout)
    (negative / "native.stderr").write_text(refused.stderr)
    predicate = "publication_matrix: assertion failed (blocked == 0): (1 == 0)"
    if refused.returncode != -signal.SIGABRT or predicate not in (
        refused.stdout + refused.stderr
    ):
        raise ValueError("settlement mutation missed its exact native assertion")
    print("PASS settlement guard mutation: actual SIGABRT at blocked 1 versus 0")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--build-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--nm", type=Path, required=True)
    arguments = parser.parse_args()
    environment = os.environ.copy()
    environment["LDFLAGS"] = configured_support(arguments.build_root, environment)
    command = [
        sys.executable,
        str(arguments.source_root / "tests/unit/test-crucible-settle-prepark.py"),
        "--source-root", str(arguments.source_root),
        "--output-dir", str(arguments.output_dir),
    ]
    subprocess.run(
        command, cwd=arguments.build_root, env=environment, check=True,
    )
    check_component_symbols(
        arguments.output_dir, arguments.build_root, environment, arguments.nm,
    )
    check_negative_control(
        command, arguments.output_dir, arguments.build_root, environment,
    )


if __name__ == "__main__":
    main()
