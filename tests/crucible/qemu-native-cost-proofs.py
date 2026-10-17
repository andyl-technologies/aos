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


def check_reviewed_adaptation(source_root, manifest):
    """Pin the reviewed source additions without changing any baseline hash."""
    adaptation = manifest.get("reviewedAdaptation")
    if adaptation is None:
        return None

    header_path = "include/qemu/crucible-fault.h"
    expected_paths = {header_path, "plugins/crucible-fault-clock.c"}
    if set(adaptation["files"]) != expected_paths:
        raise ValueError("unreviewed native-cost reconstruction adaptation")
    for field in ("revision", "tree"):
        if not re.fullmatch(r"[0-9a-f]{40}", adaptation[field]):
            raise ValueError("invalid reviewed source provenance")
    for relative_path, expected_hash in adaptation["files"].items():
        checked_reference(source_root / relative_path, expected_hash)

    header = (source_root / header_path).read_bytes()
    addition = adaptation["headerAddition"].encode("utf-8")
    if not addition or header.count(addition) != 1:
        raise ValueError("reviewed header addition is missing or ambiguous")
    original_header = header.replace(addition, b"", 1)
    if hashlib.sha256(original_header).hexdigest() != manifest["files"][header_path]:
        raise ValueError("reviewed header addition changes frozen declarations")
    return header_path


def reconstruct_baseline(args):
    """Reverse only the reviewed native hunks and verify exact retained files."""
    manifest = json.loads(args.baseline_manifest.read_text())
    checked_reference(args.baseline_patch, manifest["patchSha256"])
    adapted_header = check_reviewed_adaptation(args.source_root, manifest)
    baseline_root = args.output_dir / "baseline-source"
    for relative_path in manifest["files"]:
        target = baseline_root / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(args.source_root / relative_path, target)
    shutil.copytree(
        args.source_root / "include/qemu", baseline_root / "include/qemu",
        dirs_exist_ok=True,
    )
    # The retained delta is baseline-to-candidate. Refuse implicit direction
    # recovery so reconstruction uses only the explicit reverse operation.
    reconstruction = subprocess.run(
        ["patch", "--batch", "--force", "--reverse", "--fuzz=0", "-p1", "-i",
         str(args.baseline_patch.resolve())],
        cwd=baseline_root, capture_output=True, text=True,
    )
    (args.output_dir / "baseline-reconstruction.stdout").write_text(reconstruction.stdout)
    (args.output_dir / "baseline-reconstruction.stderr").write_text(reconstruction.stderr)
    reconstruction.check_returncode()
    for relative_path, expected_hash in manifest["files"].items():
        checked_reference(baseline_root / relative_path, expected_hash)
    # All original declarations and compiler macros remain identical. The
    # singleton reviewed prototype was verified against the frozen header above.
    for relative_path, expected_hash in manifest["files"].items():
        if relative_path.endswith(".h") and relative_path != adapted_header:
            checked_reference(args.source_root / relative_path, expected_hash)
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
        executable_name = {
            "test-crucible-mutex-waiter-counters.py": "mutex-waiter-counters",
            "test-crucible-tcg-page-collection.py": "page-collection",
            "test-crucible-tcg-crossing-membership.py": "crossing-membership",
            "test-crucible-tsc-source-index.py": "tsc-source-index",
        }[Path(command[1]).name]
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
        elif (directory / "stderr.txt").is_file():
            if "SIGABRT" not in completed.stderr:
                raise AssertionError("negative native fixture child did not abort")
            native_stderr = (directory / "stderr.txt").read_text()
        elif executable_name == "tsc-source-index":
            if "SIGABRT" not in completed.stderr:
                raise AssertionError("negative native TSC child did not abort")
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


def diagnostic_counts(stderr, label):
    """Read named native counters without discarding any retained diagnostics."""
    prefix = f"{label}: "
    lines = [line for line in stderr.splitlines() if line.startswith(prefix)]
    if len(lines) != 1:
        raise AssertionError(f"expected one native diagnostic for {label}")
    return {key: int(value) for key, value in
            (field.split("=", 1) for field in lines[0][len(prefix):].split())}


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
    expected_labels = [
        "absent", "first-page-zero", "empty", "single-page", "physical-alias",
        "tag-zero", "tag-one", "reverse-order", "retry", "dedup-and-range",
        "below-capacity", "at-capacity", "spill", "missing-at-capacity",
        "duplicates-at-capacity", "reverse-order-spill", "busy-before-spill",
        "busy-on-spill", "busy-after-spill", "precise-exit-inline",
        "precise-exit-spill",
    ]
    labels = [line.split(":", 1)[0] for line in positive.stdout.splitlines()[:-1]]
    if labels != expected_labels:
        raise AssertionError("native page collection case coverage differs")
    baseline_counts = diagnostic_counts(baseline.stderr, "single-page")
    positive_counts = diagnostic_counts(positive.stderr, "single-page")
    if any(baseline_counts.get(key) != value for key, value in
           {"tree-lookups": 65, "trees": 1, "entries": 1}.items()):
        raise AssertionError("baseline redundant page lookup witness differs")
    if any(positive_counts.get(key) != 0 for key in
           ("tree-lookups", "trees", "entries", "memberships")):
        raise AssertionError("inline page allocation and lookup witness differs")

    negatives = [
        "omit-other-page", "drop-spill-state", "skip-inline-unlock",
        "reverse-inline-iteration", "omit-empty-admission", "eager-tree",
    ]
    for mutation in negatives:
        directory = args.output_dir / f"negative-{mutation}"
        negative = run_fixture(
            [sys.executable, str(fixture), "--output-dir", str(directory),
             "--negative", mutation], directory, negative=True,
        )
        if "page-collection: passed" in negative.stdout:
            raise AssertionError("causal negative emitted the success marker")
    return {
        "lock_trace_equal": True,
        "page_cases": len(labels),
        "page_case_labels": labels,
        "single_page_baseline_tree_lookups": 65,
        "single_page_optimized_tree_lookups": 0,
        "single_page_baseline_trees": 1,
        "single_page_optimized_trees": 0,
        "single_page_baseline_heap_entries": 1,
        "single_page_optimized_heap_entries": 0,
        "single_page_optimized_membership_visits": 0,
        "inline_capacity": 4,
        "compiled_causal_negatives": negatives,
        "precise_smc_cleanup": ["inline", "spill"],
        "scope": "extracted-production-page-collection-with-glib-and-pthreads",
    }


def check_crossing_membership(args, baseline_root):
    """Require native mutation bookkeeping and fresh discovery after retry."""
    collection_fixture = args.source_root / "tests/unit/test-crucible-tcg-page-collection.py"
    fixture = args.source_root / "tests/unit/test-crucible-tcg-crossing-membership.py"
    baseline_dir = args.output_dir / "reference"
    baseline = run_fixture(
        [sys.executable, str(collection_fixture), "--source-root", str(baseline_root),
         "--output-dir", str(baseline_dir)], baseline_dir,
    )
    positive = run_fixture(
        [sys.executable, str(fixture), "--source-root", str(args.source_root),
         "--output-dir", str(args.output_dir)], args.output_dir,
    )
    baseline_lines = baseline.stdout.splitlines()
    positive_lines = positive.stdout.splitlines()
    if (len(baseline_lines) != 22 or baseline_lines[-1] != "page-collection: passed"
            or positive_lines[:len(baseline_lines)] != baseline_lines):
        raise AssertionError("membership proof native collection traces differ from baseline")
    if positive_lines[-1] != "crossing-membership: passed":
        raise AssertionError("native crossing membership success marker absent")

    expected_labels = [
        "mixed-crossing", "last-crossing-removed", "membership-tags-aliases-mixed",
        "membership-native-qht-rollback", "retained-invalid",
        "membership-native-retained-invalid", "sticky-unknown", "after-flush",
        "membership-saturation-empty-flush", "retry-list-mutated",
        "membership-retry-fresh-count", "membership-retained-fork-copy",
    ]
    labels = [line.split(":", 1)[0]
              for line in positive_lines[len(baseline_lines):-1]]
    if labels != expected_labels:
        raise AssertionError("native membership mutation coverage differs")
    for label in ("single-page", "last-crossing-removed", "after-flush"):
        if diagnostic_counts(positive.stderr, label).get("memberships") != 0:
            raise AssertionError(f"zero crossing count still scanned memberships: {label}")
    if diagnostic_counts(positive.stderr, "sticky-unknown").get("memberships", 0) <= 0:
        raise AssertionError("saturated crossing count skipped required discovery")

    negatives = [
        "omit-increment", "premature-zero", "wrap-count", "miss-empty-reset",
        "miss-flush-reset", "decrement-hash-only", "cache-across-retry",
    ]
    for mutation in negatives:
        directory = args.output_dir / f"negative-{mutation}"
        negative = run_fixture(
            [sys.executable, str(fixture), "--source-root", str(args.source_root),
             "--output-dir", str(directory), "--negative", mutation],
            directory, negative=True,
        )
        if "crossing-membership: passed" in negative.stdout:
            raise AssertionError("membership causal negative emitted the success marker")
    return {
        "lock_trace_equal": True,
        "inherited_collection_cases": len(baseline_lines) - 1,
        "membership_observation_labels": labels,
        "compiled_causal_negatives": negatives,
        "zero_count_skips_membership_walk": True,
        "saturated_count_retains_membership_walk": True,
        "ordinary_process_fork_copy": True,
        "full_hot_fork_lifecycle": False,
        "scope": "extracted-production-membership-mutations-with-explicit-external-providers",
    }


def check_tsc_source_index(args, baseline_root):
    """Compare live TSC observations while rejecting stale search hints."""
    fixture = args.source_root / "tests/unit/test-crucible-tsc-source-index.py"
    reference_dir = args.output_dir / "reference"
    reference = run_fixture(
        [sys.executable, str(fixture), "--source-root", str(baseline_root),
         "--output-dir", str(reference_dir)], reference_dir,
    )
    positive = run_fixture(
        [sys.executable, str(fixture), "--source-root", str(args.source_root),
         "--output-dir", str(args.output_dir)], args.output_dir,
    )
    observations = [
        "unsealed applicability, exact keys and absent lookup: passed",
        "live backing storage and production manifest sorting: passed",
        "live activation, restore-depth guards, values and terminal failure: passed",
        "native fork private rows, inherited hint and cold replacement thread: passed",
        "empty and adversarial shrink bounds: passed",
    ]
    expected_stdout = "\n".join(observations) + "\n"
    if reference.stdout != expected_stdout or positive.stdout != expected_stdout:
        raise AssertionError("native TSC lifecycle observations differ from baseline")
    if reference.stderr.splitlines() != ["unsealed-second-lookup: row-reads=5"]:
        raise AssertionError("baseline unsealed TSC search count differs")
    if positive.stderr.splitlines() != ["unsealed-second-lookup: row-reads=1"]:
        raise AssertionError("validated TSC search hint count differs")

    manifest = json.loads(args.baseline_manifest.read_text())
    clock_reference = manifest["clockReference"]
    checked_reference(
        baseline_root / "plugins/crucible-fault-clock.c",
        clock_reference["sha256"],
    )
    negatives = [
        "preseal-gate", "omit-bounds", "omit-instance", "omit-kind",
        "stale-slot", "shared-hint", "activation-before-load",
        "stale-pointer", "negative-cache",
    ]
    for mutation in negatives:
        directory = args.output_dir / f"negative-{mutation}"
        run_fixture(
            [sys.executable, str(fixture), "--source-root", str(args.source_root),
             "--output-dir", str(directory), "--negative", mutation],
            directory, negative=True,
        )
    return {
        "lifecycle_observations_equal": True,
        "lifecycle_observations": observations,
        "unsealed_second_lookup_baseline_row_reads": 5,
        "unsealed_second_lookup_validated_hint_row_reads": 1,
        "identical_clock_reference": clock_reference,
        "compiled_causal_negatives": negatives,
        "native_process_fork_and_replacement_thread": True,
        "concurrent_registry_mutation": False,
        "full_retained_runtime_or_migration_stream": False,
        "scope": "extracted-production-tsc-lookup-with-quiescent-registry-providers",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=["mutex-waiter-counters", "tcg-page-collection",
                                          "tcg-crossing-membership", "tsc-source-index"],
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
    check = {
        "mutex-waiter-counters": check_mutex,
        "tcg-page-collection": check_pages,
        "tcg-crossing-membership": check_crossing_membership,
        "tsc-source-index": check_tsc_source_index,
    }[args.case]
    result = check(args, baseline_root)
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
