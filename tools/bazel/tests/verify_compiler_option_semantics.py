"""Checks selected option semantics against the declared Rust compiler."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from verify_compiler_options import compiler_options


def inspect(rustc, directory):
    """Requires additive metadata and scalar/default behavior in actual rustc runs."""
    source = directory / "probe.rs"
    source.write_text(
        "#![no_std]\n\n"
        "pub fn identity(value: u64) -> u64 {\n"
        "    value\n"
        "}\n"
    )
    output = directory / "probe.ll"
    common = [
        str(rustc), "--crate-name", "option_probe", "--crate-type", "rlib",
        "--edition=2024", "--emit=llvm-ir", "-Ccodegen-units=1", str(source),
        "-o", str(output),
    ]
    metadata = {
        "repeated": ["-Cmetadata=first", "-Cmetadata=second"],
        "combined": ["-Cmetadata=first second"],
        "last_only": ["-Cmetadata=second"],
    }
    ir = {}
    commands = {}
    for name, arguments in metadata.items():
        command = [*common, *arguments]
        subprocess.run(command, check=True, capture_output=True, text=True, timeout=60)
        ir[name] = output.read_bytes()
        commands[name] = command

    if ir["repeated"] != ir["combined"] or ir["repeated"] == ir["last_only"]:
        raise ValueError("declared rustc does not exhibit the expected additive metadata behavior")
    options = compiler_options(metadata["repeated"])
    if "metadata" in options["effective_scalar_codegen"]:
        raise ValueError("metadata was incorrectly classified as a scalar override")
    if options["codegen"] != ["metadata=first", "metadata=second"]:
        raise ValueError("ordered metadata evidence lost a value")

    probes = {
        "debug_last_enabled": (["-Cdebug-assertions=no", "-Cdebug-assertions=yes"], True),
        "debug_last_disabled": (["-Cdebug-assertions=yes", "-Cdebug-assertions=no"], False),
        "optimized_default": (["-Copt-level=0", "-Copt-level=3"], False),
        "unoptimized_default": (["-Copt-level=3", "-Copt-level=0"], True),
    }
    cfg = {}
    for name, (arguments, expected) in probes.items():
        command = [str(rustc), "--print", "cfg", *arguments]
        result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=60)
        values = result.stdout.splitlines()
        if ("debug_assertions" in values) != expected:
            raise ValueError("declared rustc debug-assertion behavior differs: " + name)
        parsed = compiler_options(arguments)["effective_scalar_codegen"]
        if "debug-assertions" in parsed:
            observed = parsed["debug-assertions"] == "yes"
        else:
            observed = parsed["opt-level"] == "0"
        if observed != expected:
            raise ValueError("option evidence disagrees with declared rustc: " + name)
        cfg[name] = {"command": command, "cfg": values, "scalar_options": parsed}

    version = subprocess.run(
        [str(rustc), "--version", "--verbose"], check=True,
        capture_output=True, text=True, timeout=60,
    )
    return {
        "schema_version": 1,
        "status": "PASS",
        "rustc": str(rustc),
        "version": version.stdout,
        "probe_source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "metadata": {
            name: {"command": commands[name], "llvm_ir_sha256": hashlib.sha256(content).hexdigest()}
            for name, content in ir.items()
        },
        "cfg_probes": cfg,
        "limits": [
            "These probes check additive metadata, scalar overrides, and optimization-dependent debug assertions on the declared native compiler.",
            "They do not establish full compiler-default, target, linker, or runtime equivalence between build systems.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rustc", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="rust-option-semantics-") as temporary:
        report = inspect(arguments.rustc, Path(temporary))
    arguments.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
