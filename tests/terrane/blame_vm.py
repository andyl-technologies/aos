"""Executes the original SDK and CLI graph-audit selectors in an ext4 guest."""

import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys
import tempfile


CASES = {
    "sdk": [
        "blame_requires_only_selected_root_read_and_refuses_other_scopes",
        "blame_uses_signed_metadata_without_requesting_object_bodies",
    ],
    "cli-tests": [
        "local_blame_preserves_introduction_through_merges_and_refuses_unauthorized_output",
    ],
}


def main():
    """Checks source, original launch paths and exact nonignored test execution."""
    sys.dont_write_bytecode = True
    image, source = map(Path, sys.argv[1:])
    helpers = runpy.run_path(str(source / "tests/terrane/blame_test_image.py"))
    identity_check = runpy.run_path(str(source / "tests/terrane/host_cache_selector_vm.py"))["check_identity"]
    check_output = runpy.run_path(str(source / "tests/terrane/check_native_gate.py"))["check_output"]
    identity_check()
    identity = helpers["verify"](image, source)
    storage = Path(os.environ["TMPDIR"])
    filesystem = subprocess.check_output([
        "findmnt", "--noheadings", "--output", "FSTYPE", "--target", str(storage),
    ], text=True).strip()
    assert filesystem == "ext4"
    cli_path = Path(identity["artifacts"]["cli"]["original_executable"])
    assert cli_path.is_symlink() and cli_path.resolve() == image / "bin/cli"
    os.chdir(source / "crates")

    for target, cases in CASES.items():
        binary = image / "bin" / target
        inventory = subprocess.run([str(binary), "--list"], check=True, text=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=5)
        check_output("inventory", inventory.stdout, cases)
        assert all(inventory.stdout.splitlines().count(case + ": test") == 1 for case in cases)
        for case in cases:
            with tempfile.TemporaryDirectory(prefix="blame-case-", dir=storage) as directory:
                result = subprocess.run([
                    str(binary), case, "--exact", "--test-threads=1",
                ], env=dict(os.environ, TMPDIR=directory), text=True,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
                print(result.stdout, end="", flush=True)
                result.check_returncode()
                check_output("execution", result.stdout, [case])
                assert re.findall(r"^test (.+) \.\.\. ok$", result.stdout, re.MULTILINE) == [case]
                assert len(re.findall(r"^test result: ok\. 1 passed; 0 failed; 0 ignored;",
                                      result.stdout, re.MULTILINE)) == 1

    identity_check()
    assert helpers["verify"](image, source) == identity
    print("BLAME_PROOF " + json.dumps({
        "source": str(source), "image": str(image), "cases": CASES,
        "uid": os.getuid(), "gid": os.getgid(), "capabilities": 0,
        "no_new_privileges": True, "filesystem": filesystem,
        "binaries": {name: artifact["binary_sha256"]
                     for name, artifact in identity["artifacts"].items()},
    }, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
