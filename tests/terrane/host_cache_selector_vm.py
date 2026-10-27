"""Executes each host-cache gate's original exact selectors in its ext4 guest."""

import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile


def check_identity():
    """Requires the guest's original unprivileged process boundary."""
    assert os.getuid() == os.geteuid() == 840
    assert os.getgid() == os.getegid() == 840 and os.getgroups() == []
    status = dict(line.split(":", 1) for line in Path("/proc/self/status")
                  .read_text().splitlines() if ":" in line)
    for name in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"]:
        assert int(status[name].strip(), 16) == 0, name
    assert status["NoNewPrivs"].strip() == "1"


def main():
    """Checks immutable source and executable identity around the complete suite."""
    image, source = map(Path, sys.argv[1:3])
    suite = sys.argv[3]
    cases = json.loads(Path(sys.argv[4]).read_text())
    assert isinstance(cases, list) and cases
    assert all(isinstance(case, str) and case.startswith("host::cache::") for case in cases)
    assert len(set(cases)) == len(cases)
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
    assert all(inventory.stdout.splitlines().count(case + ": test") == 1 for case in cases)

    for case in cases:
        # A case receives its own empty directory, retaining the owning gate's isolation.
        with tempfile.TemporaryDirectory(prefix="host-cache-case-", dir=storage) as directory:
            result = subprocess.run([
                str(binary), case, "--exact", "--test-threads=1",
            ], env=dict(os.environ, TMPDIR=directory), text=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
            print(result.stdout, end="", flush=True)
            result.check_returncode()
            check_output("execution", result.stdout, [case])
            lines = result.stdout.splitlines()
            assert lines.count("test " + case + " ... ok") == 1
            summaries = [line for line in lines if line.startswith("test result:")]
            assert len(summaries) == 1
            assert summaries[0].startswith("test result: ok. 1 passed; 0 failed; 0 ignored;")

    check_identity()
    assert verify_image(source, image) == binary_hash
    print("HOST_CACHE_SELECTOR_PROOF " + json.dumps({
        "suite": suite, "source": str(source), "image": str(image), "cases": cases,
        "uid": os.getuid(), "gid": os.getgid(), "capabilities": 0,
        "no_new_privileges": True, "filesystem": filesystem,
        "binary_sha256": binary_hash,
    }, sort_keys=True), flush=True)
    print(f"PASS complete {suite} selectors execute in the original UID-840 ext4 guest",
          flush=True)


if __name__ == "__main__":
    main()
