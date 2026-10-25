"""Runs the complete shared-directory selector inventories in an ext4 guest."""

import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile


PREFIX = "store::shared_dir::native_tests::"
SUITES = {
    "read-only": [
        "existing_directory_reads_and_rejected_puts_leave_bytes_and_names_unchanged",
        "corrupt_existing_chunk_is_never_returned_or_repaired",
        "explicit_read_budget_returns_capacity_without_mutating_valid_content",
        "exact_encoded_ranges_verify_the_complete_chunk_before_returning_bytes",
        "manifest_get_returns_canonical_metadata_instead_of_sealed_plaintext",
        "residence_composition::portable_composition_recovers_encoded_chunk_after_ordinary_body_removal",
        "residence_composition::portable_residence_never_masks_corruption_or_substitutes_manifest_plaintext",
    ],
    "isolation": [
        "domain_routes_never_probe_another_directory_or_unreachable_identity",
        "same_domain_snapshots_read_one_existing_inode_without_extending_reachability",
        "routes_refuse_two_domain_labels_for_the_same_directory",
        "directory_and_body_symlinks_cannot_cross_domain_boundaries",
        "shared_private_open_refuses_before_touching_missing_root",
        "residence_composition::portable_resident_routes_preserve_domain_and_reachability_before_lookup",
    ],
}


def check_identity():
    """Checks original guest credentials and the inherited irreversible boundary."""
    assert os.getuid() == os.geteuid() == 840
    assert os.getgid() == os.getegid() == 840 and os.getgroups() == []
    status = dict(line.split(":", 1) for line in Path("/proc/self/status")
                  .read_text().splitlines() if ":" in line)
    for name in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"]:
        assert int(status[name].strip(), 16) == 0, name
    assert status["NoNewPrivs"].strip() == "1"


def main():
    """Binds the retained Cargo artifact before executing each original case."""
    image, source = map(Path, sys.argv[1:3])
    suite = sys.argv[3]
    cases = [PREFIX + name for name in SUITES[suite]]
    sys.dont_write_bytecode = True
    check_identity()
    storage = Path(os.environ["TMPDIR"])
    filesystem = subprocess.check_output([
        "findmnt", "--noheadings", "--output", "FSTYPE", "--target", str(storage),
    ], text=True).strip()
    assert filesystem == "ext4"
    verify_image = runpy.run_path(str(source / "tests/terrane/local_collection_vm.py"))["verify_image"]
    binary_hash = verify_image(source, image)
    check_output = runpy.run_path(str(source / "tests/terrane/check_native_gate.py"))["check_output"]
    binary = image / "bin/terrane-native-sdk-tests"
    os.chdir(source / "crates")
    inventory = subprocess.run([str(binary), "--list"], check=True, text=True,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=5)
    check_output("inventory", inventory.stdout, cases)

    for case in cases:
        # Each original case owns fresh private storage, as in the owning gate.
        with tempfile.TemporaryDirectory(prefix="shared-case-", dir=storage) as directory:
            result = subprocess.run([
                str(binary), case, "--exact", "--test-threads=1",
            ], env=dict(os.environ, TMPDIR=directory), text=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
            print(result.stdout, end="", flush=True)
            result.check_returncode()
            check_output("execution", result.stdout, [case])

    check_identity()
    assert verify_image(source, image) == binary_hash
    print("SHARED_DIRECTORY_PROOF " + json.dumps({
        "suite": suite, "source": str(source), "image": str(image), "cases": cases,
        "uid": os.getuid(), "gid": os.getgid(), "capabilities": 0,
        "no_new_privileges": True, "filesystem": filesystem,
        "binary_sha256": binary_hash,
    }, sort_keys=True), flush=True)
    print(f"PASS complete shared-directory {suite} selectors execute in the original UID-840 ext4 guest",
          flush=True)


if __name__ == "__main__":
    main()
