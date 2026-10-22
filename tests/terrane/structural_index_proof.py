"""Binds the structural codec's hostile-byte tests to actual source and ELF bytes."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from native_sdk_test_image import source_hashes


CASES = [
    "nested_tree_has_sorted_paths_and_contiguous_direct_child_indices",
    "content_kind_size_symlink_bytes_and_graft_governance_survive_roundtrip",
    "empty_tree_and_exact_compiler_bounds_are_supported",
    "compiler_rejects_missing_nondirectory_duplicate_and_invalid_paths",
    "every_truncation_and_hostile_header_offset_is_rejected",
    "forged_parent_child_and_arena_relationships_are_rejected",
    "arbitrary_short_inputs_and_single_byte_mutations_never_panic",
]
PREFIX = "structural_index::tests::"


def require(condition, message):
    """Rejects mismatched or incomplete execution evidence."""
    if not condition:
        raise SystemExit(message)


def main():
    """Checks one source-bound Linux library artifact and all codec selectors."""
    output = Path(os.environ["out"])
    source = Path(os.environ["src"])
    workspace = Path.cwd()
    inputs = source_hashes(workspace, source)
    rows = [json.loads(line) for line in (output / "build.jsonl").read_text().splitlines()]
    artifacts = [row for row in rows if row.get("reason") == "compiler-artifact"
                 and row.get("target", {}).get("name") == "terrane_linux"
                 and row.get("executable")]
    require(len(artifacts) == 1, "ambiguous structural index test artifact")
    artifact = artifacts[0]
    profile = artifact["profile"]
    require(artifact["target"]["kind"] == ["lib"]
            and Path(artifact["target"]["src_path"]) == workspace / "terrane/linux/terrane-linux/src/lib.rs"
            and artifact["package_id"].startswith("path+file://" + str(workspace / "terrane/linux/terrane-linux") + "#")
            and artifact["features"] == ["surface-fuse"]
            and profile["test"] and profile["opt_level"] == "s"
            and profile["debuginfo"] == 0 and profile["debug_assertions"],
            "structural index artifact source, features or profile mismatch")
    executable = Path(artifact["executable"])
    require(executable.resolve().is_relative_to(Path(os.environ["CARGO_TARGET_DIR"]).resolve())
            and executable.read_bytes().startswith(b"\x7fELF"), "invalid structural index test ELF")
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()

    def captured(arguments, name):
        with (output / name).open("w") as log:
            result = subprocess.run([str(executable), *arguments], stdout=log,
                                    stderr=subprocess.STDOUT, timeout=30)
        text = (output / name).read_text()
        sys.stdout.write(text)
        require(result.returncode == 0, "structural index selector failed")
        return text.splitlines()

    cases = [PREFIX + case for case in CASES]
    inventory = captured([PREFIX, "--list", "--format", "terse"], "inventory.log")
    actual = [line.removesuffix(": test") for line in inventory if line.endswith(": test")]
    require(len(actual) == len(set(actual)) == len(cases) and set(actual) == set(cases),
            "structural index inventory changed")
    for case in cases:
        lines = captured([case, "--exact", "--nocapture", "--test-threads=1"], case + ".log")
        require(lines.count("test " + case + " ... ok") == 1
                and sum(line.startswith("test result:") for line in lines) == 1
                and sum(line.startswith("test result: ok. 1 passed; 0 failed; 0 ignored;")
                        for line in lines) == 1, "structural index case did not execute once")
    require(hashlib.sha256(executable.read_bytes()).hexdigest() == digest,
            "structural index test ELF changed")
    require(source_hashes(workspace, source) == inputs, "structural index source changed")
    (output / "source-review.json").write_text(json.dumps({
        "source": str(source), "input_sha256": inputs, "artifact": artifact,
        "executable_sha256": digest, "executed_cases": cases,
        "scope": "Structural codec only; no sealed mapping, cache lease or FUSE worker authority",
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
