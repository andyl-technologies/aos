"""Generates and validates weighted LLVM profiles using an instrumented fixture."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from verify_cache import package_files


def train(build, profdata, rustc, output):
    """Requires matching source-built tools and actual shared-library counters."""
    rust_version = subprocess.run([str(rustc), "-vV"], check=True, capture_output=True, text=True).stdout
    llvm_version = subprocess.run([str(profdata), "--version"], check=True, capture_output=True, text=True).stdout
    rust_llvm = re.search(r"LLVM version: ([0-9.]+)", rust_version)
    llvm = re.search(r"LLVM version ([0-9.]+)", llvm_version)
    if not rust_llvm or not llvm or rust_llvm[1] != llvm[1]:
        raise ValueError("PGO requires the Rust compiler's matching LLVM profile format")
    executable = package_files(build)["bin/rust-fixture"]
    records = {}
    for name, repetitions in [("baseline", 1), ("changed", 4)]:
        scratch = Path(name).resolve()
        scratch.mkdir()
        environment = dict(os.environ, LLVM_PROFILE_FILE=str(scratch / "fixture-%m-%p.profraw"))
        for _ in range(repetitions):
            result = subprocess.run([str(executable)], check=True, capture_output=True, text=True,
                                    env=environment, cwd=scratch, timeout=60)
            if result.stdout.strip() != "answer=42":
                raise ValueError("instrumented fixture changed runtime behavior")
        raw = sorted(scratch.glob("*.profraw"))
        if len(raw) != repetitions:
            raise ValueError("instrumented executions did not emit separate raw profiles")
        merged = output / (name + ".profdata")
        subprocess.run([str(profdata), "merge", "-o", str(merged), *map(str, raw)], check=True, timeout=60)
        shown = subprocess.run([str(profdata), "show", "--function=fixture_library", "--counts", str(merged)],
                               check=True, capture_output=True, text=True, timeout=30)
        counts = [int(value.strip())
                  for block in re.findall(r"Block counts: \[([0-9, ]+)\]", shown.stdout)
                  for value in block.split(",")]
        if not re.search(r"fixture_library[^\n]*answer", shown.stdout) or not counts or not any(count > 0 for count in counts):
            raise ValueError("profile omitted executed first-party library functions")
        (output / (name + ".txt")).write_text(shown.stdout)
        records[name] = {"sha256": hashlib.sha256(merged.read_bytes()).hexdigest(),
                         "executions": repetitions, "block_counts": counts}
    if records["baseline"]["sha256"] == records["changed"]["sha256"]:
        raise ValueError("different training weights produced identical profile inputs")
    if records["changed"]["block_counts"] != [4 * count for count in records["baseline"]["block_counts"]]:
        raise ValueError("profile counters do not reflect the controlled training weights")
    return {"schema_version": 1, "build": str(build), "rust_version": rust_version,
            "llvm_version": llvm_version, "profiles": records}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["build", "profdata", "rustc", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    options = parser.parse_args()
    options.output.mkdir(parents=True, exist_ok=True)
    report = train(options.build, options.profdata, options.rustc, options.output)
    (options.output / "profiles.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
