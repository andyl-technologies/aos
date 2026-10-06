# SPDX-License-Identifier: Apache-2.0
"""Compare extracted native bodies and require compiled causal failures.

The GPL-side fixtures own every extracted production definition. This host
runner verifies immutable baseline inputs and their emitted observations;
guest execution remains a separate package and native qualification check.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys


def checked_reference(path, expected_hash):
    """Reject a baseline source file that differs from its recorded revision."""
    observed_hash = hashlib.sha256(path.read_bytes()).hexdigest()
    if observed_hash != expected_hash:
        raise ValueError(f"baseline source digest mismatch for {path.name}")
    return observed_hash


def reconstruct_baseline(args):
    """Reverse only the reviewed native hunks and verify exact retained files."""
    manifest = json.loads(args.baseline_manifest.read_text())
    checked_reference(args.baseline_patch, manifest["patchSha256"])
    baseline_root = args.output_dir / "baseline-source"
    for relative_path in manifest["files"]:
        target = baseline_root / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(args.source_root / relative_path, target)
    shutil.copytree(args.source_root / "include/qemu", baseline_root / "include/qemu")
    reconstruction = subprocess.run(
        ["patch", "--batch", "--reverse", "--fuzz=0", "-p1", "-i",
         str(args.baseline_patch.resolve())],
        cwd=baseline_root, capture_output=True, text=True,
    )
    (args.output_dir / "baseline-reconstruction.stdout").write_text(reconstruction.stdout)
    (args.output_dir / "baseline-reconstruction.stderr").write_text(reconstruction.stderr)
    reconstruction.check_returncode()
    for relative_path, expected_hash in manifest["files"].items():
        checked_reference(baseline_root / relative_path, expected_hash)
    # Both variants use the same translation-block header, without adaptation.
    checked_reference(
        args.source_root / "include/exec/translation-block.h",
        manifest["files"]["include/exec/translation-block.h"],
    )
    (args.output_dir / "baseline-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n"
    )
    return baseline_root, manifest


def run_fixture(command, directory, negative=False):
    """Retain full output and distinguish native assertions from setup errors."""
    directory.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(command, capture_output=True, text=True, timeout=120)
    (directory / "fixture.stdout").write_text(completed.stdout)
    (directory / "fixture.stderr").write_text(completed.stderr)
    (directory / "fixture-status.json").write_text(
        json.dumps({"returncode": completed.returncode}, indent=2) + "\n"
    )
    if negative:
        executable_name = (
            "mutex-waiter-counters" if "mutex-waiter" in command[1]
            else "page-collection"
        )
        if not (directory / executable_name).is_file():
            raise AssertionError("negative control did not compile its native executable")
        if completed.returncode == 0:
            raise AssertionError("negative control unexpectedly passed")
        native_stderr = completed.stderr
        retained_stderr = directory / "run.stderr"
        if retained_stderr.is_file():
            # The waiter fixture captures its native child's output before
            # raising. Require that child's abort, not the wrapper traceback.
            native_status = json.loads((directory / "run-status.json").read_text())
            if native_status["returncode"] != -signal.SIGABRT:
                raise AssertionError("negative native child did not abort")
            native_stderr = retained_stderr.read_text()
        if not re.search(
            r"assertion failed|Assertion .* failed|should (?:not )?be",
            native_stderr,
            re.IGNORECASE,
        ):
            raise AssertionError("negative control failed without a native assertion")
    else:
        completed.check_returncode()
    return completed


def check_mutex(args, baseline_root):
    """Compare guarded inventories and reject each missing counter update."""
    fixture = args.source_root / "tests/unit/test-crucible-mutex-waiter-counters.py"
    command = [sys.executable, str(fixture), "--output-dir", str(args.output_dir)]
    positive = run_fixture(
        command + ["--reference-source", str(baseline_root / "util/qemu-thread-posix.c")],
        args.output_dir,
    )
    reference = (args.output_dir / "reference/trace.txt").read_text()
    if positive.stdout != reference:
        raise AssertionError("native waiter inventory traces differ")
    labels = [line.split()[0] for line in positive.stdout.splitlines()]
    expected_labels = [
        "admitted", "native-acquired", "unlock-begin", "native-unlocked",
        "completed", "failed-trylock", "successful-trylock", "condition-one",
        "condition-two", "condition-completed", "condition-timeout",
        "contended-completed", "cancel-underflow", "acquired-underflow",
        "acquisition-wrap", "condition-wrap", "condition-underflow",
    ]
    if labels != expected_labels:
        raise AssertionError("native waiter inventory case coverage differs")

    negatives = ["admission", "cancel", "acquired", "condition-begin", "condition-end"]
    for negative in negatives:
        directory = args.output_dir / f"negative-{negative}"
        run_fixture(
            [sys.executable, str(fixture), "--output-dir", str(directory),
             "--negative-control", negative], directory, negative=True,
        )
    return {
        "inventory_trace_equal": True,
        "inventory_cases": labels,
        "compiled_causal_negatives": negatives,
        "native_pthread_contention_cycles": 16000,
        "scope": "extracted-production-registry-and-pthread-operations",
    }


def check_pages(args, baseline_root):
    """Compare exact native lock traces against the retained production body."""
    fixture = args.source_root / "tests/unit/test-crucible-tcg-page-collection.py"
    baseline_dir = args.output_dir / "reference"
    baseline = run_fixture(
        [sys.executable, str(fixture), "--source-root", str(baseline_root),
         "--output-dir", str(baseline_dir)], baseline_dir,
    )
    positive = run_fixture(
        [sys.executable, str(fixture), "--output-dir", str(args.output_dir)],
        args.output_dir,
    )
    if positive.stdout != baseline.stdout:
        raise AssertionError("native page lock traces differ")
    if positive.stdout.splitlines()[-1] != "page-collection: passed":
        raise AssertionError("native page collection success marker absent")
    if len(positive.stdout.splitlines()) != 10:
        raise AssertionError("native page collection case coverage differs")
    if "single-page: tree-lookups=65" not in baseline.stderr.splitlines():
        raise AssertionError("baseline redundant page lookup witness differs")
    if "single-page: tree-lookups=1" not in positive.stderr.splitlines():
        raise AssertionError("optimized page lookup witness differs")

    negative_dir = args.output_dir / "negative-omit-other-page"
    negative = run_fixture(
        [sys.executable, str(fixture), "--output-dir", str(negative_dir),
         "--omit-other-page"], negative_dir, negative=True,
    )
    if "page-collection: passed" in negative.stdout:
        raise AssertionError("causal negative emitted the success marker")
    return {
        "lock_trace_equal": True,
        "page_cases": 9,
        "single_page_baseline_tree_lookups": 65,
        "single_page_optimized_tree_lookups": 1,
        "compiled_causal_negatives": ["omit-other-page"],
        "scope": "extracted-production-page-collection-with-glib-and-pthreads",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=["mutex-waiter-counters", "tcg-page-collection"],
                        required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--baseline-manifest", type=Path, required=True)
    parser.add_argument("--baseline-patch", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    args.source_root = args.source_root.resolve()
    args.output_dir = args.output_dir.resolve()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    baseline_root, manifest = reconstruct_baseline(args)
    result = (
        check_mutex(args, baseline_root) if args.case == "mutex-waiter-counters"
        else check_pages(args, baseline_root)
    )
    result.update({
        "status": "PASS",
        "reference_revision": manifest["revision"],
        "reference_tree": manifest["tree"],
        "reference_files": manifest["files"],
        "reference_reconstruction_patch_sha256": manifest["patchSha256"],
        "guest_execution": False,
    })
    (args.output_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"PASS production {args.case}: differential observations and compiled causal negatives")


if __name__ == "__main__":
    main()
