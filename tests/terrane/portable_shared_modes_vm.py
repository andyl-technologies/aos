"""Executes the original shared-directory setgid fixture as a real guest user."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


CASE = "bucket::portable_reader::tests::portable_reader_validates_shared_modes_without_original_control_or_effects"


def main():
    """Checks actual identity, immutable compilation inputs and exact execution."""
    image, source = map(Path, sys.argv[1:])
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(source / "tests/terrane"))
    from check_native_gate import check_output
    if os.geteuid() != 840 or os.getegid() != 840 or os.getgroups():
        raise SystemExit("shared-mode proof requires actual unprivileged guest identity")
    identity = json.loads((image / "share/identity.json").read_text())
    if (identity["source"] != str(source)
            or identity["features"] != ["default", "send", "std", "tokio"]
            or identity["profile"]["test"] is not True
            or identity["profile"]["opt_level"] != "s"):
        raise SystemExit("shared-mode SDK source, feature or profile mismatch")
    expected = {path.relative_to(source / "crates").as_posix():
                hashlib.sha256(path.read_bytes()).hexdigest()
                for path in (source / "crates").rglob("*")
                if path.is_file() and path.relative_to(source / "crates").as_posix()
                != ".cargo/config.toml"}
    if identity["input_sha256"] != expected:
        raise SystemExit("shared-mode SDK complete source binding mismatch")
    records = [json.loads(line) for line in (image / "share/build.jsonl").read_text().splitlines()]
    artifacts = [row for row in records if row.get("reason") == "compiler-artifact"
                 and row.get("target", {}).get("name") == "terrane_sdk"
                 and row.get("profile", {}).get("test") is True]
    if (len(artifacts) != 1 or artifacts[0]["profile"] != identity["profile"]
            or artifacts[0]["features"] != identity["features"]
            or artifacts[0]["package_id"] != identity["package_id"]
            or artifacts[0]["target"]["kind"] != ["lib"]
            or not (image / "libexec/terrane-native-sdk-tests").read_bytes().startswith(b"\x7fELF")):
        raise SystemExit("shared-mode SDK Cargo artifact mismatch")
    binary = image / "bin/terrane-native-sdk-tests"
    for arguments, mode in [(["--list"], "inventory"),
                            ([CASE, "--ignored", "--exact", "--nocapture", "--test-threads=1"], "execution")]:
        result = subprocess.run([str(binary), *arguments], text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
        sys.stdout.write(result.stdout)
        if result.returncode != 0:
            raise SystemExit("shared-mode guest case failed")
        check_output(mode, result.stdout, [CASE])
    print("PASS actual UID-840 setgid shared-directory reader preserves Original isolation and performs no effects")


if __name__ == "__main__":
    main()
