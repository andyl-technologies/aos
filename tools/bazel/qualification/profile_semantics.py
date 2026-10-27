"""Executes the pinned compiler's selected native test-profile defaults.

Fixtures exercise assertion and overflow behavior at runtime. Byte comparisons
isolate the selected flags and native target spelling; they do not establish
application artifact, incremental-codegen, or linker equivalence.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile


SOURCE = """fn main() {
    std::panic::set_hook(Box::new(|_| {}));

    let assertion = std::panic::catch_unwind(|| {
        debug_assert!(std::hint::black_box(false));
    }).is_err();
    let overflow = std::panic::catch_unwind(|| {
        std::hint::black_box(u8::MAX) + std::hint::black_box(1_u8)
    }).is_err();

    println!("cfg={} assertion={assertion} overflow={overflow}", cfg!(debug_assertions));
}
"""


def run(command):
    """Requires successful declared-tool execution with bounded runtime."""
    return subprocess.run(command, check=True, capture_output=True, text=True, timeout=60)


def inspect(rustc, rustc_unwrapped, cc, readelf, directory):
    """Checks runtime defaults, boolean aliases, override ordering and native cfg."""
    version = run([str(rustc), "--version", "--verbose"]).stdout
    if run([str(rustc_unwrapped), "--version", "--verbose"]).stdout != version:
        raise ValueError("wrapped and unwrapped Rust compiler versions differ")
    hosts = [line.removeprefix("host: ") for line in version.splitlines()
             if line.startswith("host: ")]
    if len(hosts) != 1 or not hosts[0].endswith("-linux-gnu"):
        raise ValueError("profile probe requires an unambiguous native GNU/Linux host")
    host = hosts[0]
    source = directory / "profile_probe.rs"
    source.write_text(SOURCE)
    output = directory / "profile-probe"
    common = [str(rustc), "--crate-name=profile_probe", "--edition=2024",
              "-Clinker=" + str(cc), str(source), "-o", str(output)]
    selected = ["-Cdebuginfo=0", "-Cdebug-assertions=yes", "-Coverflow-checks=yes"]
    disabled = (False, False, False)
    enabled = (True, True, True)
    variants = {
        "execution_implicit": (["-Cstrip=debuginfo", "-Cembed-bitcode=no"], enabled),
        "execution_explicit": (["-Copt-level=0", "-Cstrip=debuginfo", "-Cembed-bitcode=no", *selected], enabled),
        "target_native": (["-Copt-level=s", "-Cdebug-assertions=on", "-Cstrip=debuginfo", "-Cembed-bitcode=no"], enabled),
        "target_explicit": (["-Copt-level=s", "-Cstrip=debuginfo", "-Cembed-bitcode=no", *selected], enabled),
        "target_explicit_triple": (["--target", host, "-Copt-level=s", "-Cstrip=debuginfo", "-Cembed-bitcode=no", *selected], enabled),
        "optimized_implicit": (["-Copt-level=s"], disabled),
        "optimized_assertions_off": (["-Copt-level=s", "-Cdebug-assertions=off"], disabled),
        "optimized_overflow_only": (["-Copt-level=s", "-Coverflow-checks=yes"], (False, False, True)),
        "assertion_override": (["-Cdebug-assertions=no", "-Cdebug-assertions=on"], enabled),
        "overflow_override": (["-Cdebug-assertions=yes", "-Coverflow-checks=yes", "-Coverflow-checks=no"], (True, True, False)),
        "debug_implicit": ([], enabled),
        "debug_zero": (["-Cdebuginfo=0"], enabled),
        "debug_positive_control": (["-Cdebuginfo=2"], enabled),
    }
    binaries = {}
    records = {}
    for name, (flags, expected) in variants.items():
        command = [*common, *flags]
        run(command)
        binaries[name] = output.read_bytes()
        execution = run([str(output)])
        expected_stdout = "cfg={} assertion={} overflow={}\n".format(
            *(str(value).lower() for value in expected))
        if execution.stdout != expected_stdout or execution.stderr:
            raise ValueError("native profile runtime behavior differs: " + name)
        sections_command = [str(readelf), "--sections", "--wide", str(output)]
        sections_output = run(sections_command).stdout
        sections = sorted(set(re.findall(r"\[\s*\d+\]\s+(\S+)", sections_output)))
        records[name] = {
            "command": command, "runtime_stdout": execution.stdout,
            "runtime_stderr": execution.stderr, "sections": sections,
            "sections_command": sections_command,
            "sections_sha256": hashlib.sha256(sections_output.encode()).hexdigest(),
            "binary_sha256": hashlib.sha256(binaries[name]).hexdigest(),
        }
        unwrapped_command = [str(rustc_unwrapped), *command[1:]]
        run(unwrapped_command)
        unwrapped = output.read_bytes()
        if unwrapped != binaries[name]:
            raise ValueError("wrapped and unwrapped fixture binaries differ: " + name)
        records[name]["unwrapped_command"] = unwrapped_command
        records[name]["unwrapped_binary_sha256"] = hashlib.sha256(unwrapped).hexdigest()

    byte_pairs = [
        ("execution_implicit", "execution_explicit"),
        ("target_native", "target_explicit"),
        ("target_explicit", "target_explicit_triple"),
        ("optimized_implicit", "optimized_assertions_off"),
        ("debug_implicit", "debug_zero"),
    ]
    for left, right in byte_pairs:
        if binaries[left] != binaries[right]:
            raise ValueError("isolated native profile binaries differ: " + str((left, right)))
    for name in ["debug_implicit", "debug_zero", "debug_positive_control"]:
        # Linked standard-library objects can carry DWARF even when this crate
        # emits none. Inspect this source's entries rather than section presence.
        binary = directory / name
        binary.write_bytes(binaries[name])
        command = [str(readelf), "--debug-dump=info", str(binary)]
        debug = run(command).stdout
        entries = [line.strip() for line in debug.splitlines()
                   if "DW_AT_name" in line and source.name in line]
        records[name]["source_debug_entries"] = entries
        records[name]["debug_command"] = command
        records[name]["debug_sha256"] = hashlib.sha256(debug.encode()).hexdigest()
        if bool(entries) != (name == "debug_positive_control"):
            raise ValueError("implicit native debug information is not zero: " + name)

    cfg = {}
    for name, target in [("implicit", []), ("explicit", ["--target", host])]:
        command = [str(rustc), "--print=cfg", *target]
        cfg[name] = {"command": command, "values": sorted(run(command).stdout.splitlines())}
    if cfg["implicit"]["values"] != cfg["explicit"]["values"]:
        raise ValueError("implicit and explicit native target cfgs differ")

    return {
        "schema_version": 1, "status": "PASS", "rustc_version": version,
        "native_target": host, "rust_source": SOURCE,
        "tools_sha256": {str(tool): hashlib.sha256(tool.read_bytes()).hexdigest()
                         for tool in [rustc, rustc_unwrapped, cc, readelf]},
        "compiler": {"wrapped": str(rustc), "unwrapped": str(rustc_unwrapped)},
        "variants": records, "identical_binary_pairs": byte_pairs, "native_target_cfg": cfg,
        "limits": [
            "Exercises opt-level=0/s, omitted debuginfo=0, assertion boolean aliases, overflow defaults and overrides, and implicit versus explicit native target spelling.",
            "Byte comparisons isolate these settings in one executable fixture with the same declared linker and source path.",
            "Does not qualify incremental compilation, codegen-unit defaults, dependency/linker differences, application artifact equality, ABI, runtime closure, or foreign targets.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rustc", type=Path, required=True)
    parser.add_argument("--rustc-unwrapped", type=Path, required=True)
    parser.add_argument("--cc", type=Path, required=True)
    parser.add_argument("--readelf", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="aos-profile-semantics-") as directory:
        report = inspect(options.rustc, options.rustc_unwrapped, options.cc, options.readelf, Path(directory))
    options.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
