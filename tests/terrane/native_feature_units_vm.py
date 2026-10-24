"""Executes the native creator cases as the guest administrator on ext4."""

import hashlib
import json
import os
import re
import shutil
import subprocess


def execute(context):
    """Binds the remaining native feature inventory and executes every case."""
    context.require(os.geteuid() == os.getegid() == 0,
                    "native creator unit supervisor requires guest UID/GID zero")
    identity = json.loads((context.IMAGE / "share/identity.json").read_text())
    contract = context.unit_source_contract()
    unit = identity["unit_tests"]
    context.require(unit["root_inventory"] == sorted(contract["ROOT_UNIT_TESTS"])
                    and unit["full_inventory"] == sorted((*contract["ROOT_UNIT_TESTS"],
                                                          *contract["UNIT_TESTS"])),
                    "native feature inventory omits or duplicates a case")
    executable = context.IMAGE / "bin/terrane-fs-unit"
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    temporary_root = context.MOUNT / "creator-unit-tests"
    temporary_root.mkdir(mode=0o700)
    # Same real identity/capability witness as the ordinary cases, with only
    # UID/GID changed. These tests create their own initial-bucket receipts.
    launcher = context.UNIT_LAUNCHER.replace('"842"', '"0"')
    try:
        for index, name in enumerate(unit["root_inventory"]):
            temporary = temporary_root / f"case-{index:02d}"
            temporary.mkdir(mode=0o700)
            context.require(temporary.stat().st_dev == context.MOUNT.stat().st_dev,
                            "native creator unit scratch left ext4")
            environment = dict(os.environ, TMPDIR=str(temporary),
                               TERRANE_INITIAL_ENROLLMENT_TEST_ROOT=str(temporary),
                               RUST_TEST_THREADS="1")
            command = ["setpriv", "--reuid", "0", "--regid", "0", "--clear-groups",
                       "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all",
                       "--no-new-privs", context.sys.executable, "-c", launcher,
                       str(executable), "--exact", name, "--nocapture", "--test-threads=1"]
            result = subprocess.run(command, env=environment,
                                    cwd=context.SOURCE / unit["working_directory"],
                                    text=True, capture_output=True, timeout=30, close_fds=True)
            print(result.stdout, end="", flush=True)
            print(result.stderr, end="", flush=True)
            lines = result.stdout.splitlines()
            context.require(result.returncode == 0 and lines
                            and lines[0].startswith("UNIT_IDENTITY "),
                            "native creator unit failed: " + name)
            witness = json.loads(lines[0].removeprefix("UNIT_IDENTITY "))
            context.require(witness["Uid"].split() == witness["Gid"].split() == ["0"] * 4
                            and witness["Groups"] == "" and witness["NoNewPrivs"] == "1"
                            and all(int(witness[key], 16) == 0 for key in
                                    ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"]),
                            "native creator unit identity changed")
            pattern = (r"(?m)^test result: ok\. 1 passed; 0 failed; 0 ignored; "
                       r"0 measured; (\d+) filtered out; finished in .+$")
            context.require(re.findall(pattern, result.stdout)
                            == [str(len(unit["full_inventory"]) - 1)]
                            and lines.count(f"test {name} ... ok") == 1,
                            "native creator selector did not execute exactly once")
            record = {"name": name, "passed": 1, "failed": 0, "ignored": 0,
                      "identity": witness, "scratch_device": temporary.stat().st_dev,
                      "elf_sha256": digest}
            print("ROOT_FS_UNIT_RESULT " + json.dumps(record, sort_keys=True), flush=True)
            shutil.rmtree(temporary)
        context.require(hashlib.sha256(executable.read_bytes()).hexdigest() == digest,
                        "native creator unit executable changed")
        print(f"PASS all{len(unit['full_inventory'])} native feature library cases on ext4",
              flush=True)
    finally:
        shutil.rmtree(temporary_root)
