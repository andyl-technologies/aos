"""Qualifies public-key maintenance reopening on actual unprivileged guest ext4."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


CASES = [
    "configured_local_reopen_prepares_and_starts_actual_read_only_sdk",
    "local_maintenance_reopens_without_secrets_and_resumes_collection",
    "local_maintenance_refuses_foreign_trust_and_corrupt_registration",
]


def main():
    """Runs exact original Cargo cases with no signing files or fabricated authority."""
    assert os.getuid() == os.geteuid() == 840
    assert os.getgid() == os.getegid() == 840 and os.getgroups() == []
    status = dict(line.split(":", 1) for line in Path("/proc/self/status")
                  .read_text().splitlines() if ":" in line)
    for name in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"]:
        assert int(status[name].strip(), 16) == 0, name
    assert status["NoNewPrivs"].strip() == "1"
    source = Path(os.environ["src"])
    image = Path(os.environ["TERRANE_SURFACE_TEST_IMAGE"])
    evidence = Path(os.environ["TERRANE_MAINTENANCE_EVIDENCE"])
    os.chdir(source / "crates")
    verifier = [sys.executable, str(source / "tests/terrane/surface_test_image.py"),
                str(source / "tests/terrane/native_sdk_test_image.py"), "--verify", str(image)]
    subprocess.run(verifier, check=True, timeout=30)
    target = image / "targets/configured_local_repository"
    binary = target / "bin/terrane-native-sdk-tests"
    checker = source / "tests/terrane/check_native_gate.py"
    inventory = evidence / "inventory.log"
    with inventory.open("wb") as output:
        subprocess.run([str(binary), "--list"], stdout=output, stderr=subprocess.STDOUT,
                       check=True, timeout=5)
    subprocess.run([sys.executable, str(checker), "inventory", str(inventory),
                    json.dumps(CASES)], check=True, timeout=5)
    for case in CASES:
        log = evidence / (case + ".log")
        with log.open("wb") as output:
            completed = subprocess.run([str(binary), case, "--exact"],
                                       stdout=output, stderr=subprocess.STDOUT, timeout=90)
        print(log.read_text(), end="", flush=True)
        completed.check_returncode()
        subprocess.run([sys.executable, str(checker), "execution", str(log),
                        json.dumps([case])], check=True, timeout=5)
    subprocess.run(verifier, check=True, timeout=30)
    print("LOCAL_MAINTENANCE_PROOF " + json.dumps({
        "source": str(source), "image": str(image), "cases": CASES,
        "uid": os.getuid(), "capabilities": 0, "no_new_privileges": True,
        "binary_sha256": hashlib.sha256(
            (target / "libexec/terrane-native-sdk-tests").read_bytes()).hexdigest(),
        "configured_gc_runtime": False,
    }, sort_keys=True), flush=True)
    print("PASS public-key native maintenance reopen and original collection ownership; "
          "configured GC runtime remains unqualified", flush=True)


if __name__ == "__main__":
    main()
