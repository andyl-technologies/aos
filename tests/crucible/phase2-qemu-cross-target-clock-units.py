"""Authenticate the fixed configured and executed architecture timer units."""

import argparse
import json
from pathlib import Path


UNITS = {
    "test-crucible-hppa-timer-wide-clock": "hppa-softmmu",
    "test-crucible-loongarch-timer-wide-clock": "loongarch64-softmmu",
    "test-crucible-ppc-wide-clock": "ppc-softmmu",
    "test-crucible-mips-count-wide-clock": "mips64el-softmmu",
    "test-crucible-sparc-wide-clock": "sparc64-softmmu",
}


def configured(build):
    tests = json.loads((build / "meson-info/intro-tests.json").read_text())
    for name, target in UNITS.items():
        records = [test for test in tests if test["name"] == name]
        if len(records) != 1:
            raise ValueError(f"expected exactly one configured unit: {name}")
        record = records[0]
        if record["timeout"] != 30 or record["suite"] != ["qemu:unit"]:
            raise ValueError(f"registered unit contract changed: {name}")
        if not record["cmd"] or Path(record["cmd"][0]).name != name:
            raise ValueError(f"registered executable changed: {name}")
        if "--tap" not in record["cmd"] or "-k" not in record["cmd"]:
            raise ValueError(f"registered TAP arguments changed: {name}")
        header = build / f"{target}-config-target.h"
        if not header.is_file() or not header.stat().st_size:
            raise ValueError(f"missing genuine configured target header: {target}")
    print("PASS configured architecture clock units=5")


def executed(path):
    records = [json.loads(line) for line in path.read_text().splitlines() if line]
    names = [record["name"] for record in records]
    expected = {f"unit - qemu:{name}" for name in UNITS}
    if len(names) != len(UNITS) or set(names) != expected:
        raise ValueError("executed unit inventory differs from the fixed five units")
    for record in records:
        if (record["is_fail"] is not False or record["result"] != "OK"
                or record["returncode"] != 0):
            raise ValueError(f"unit did not pass: {record['name']}")
        if not record.get("stdout", "").strip():
            raise ValueError(f"unit emitted no TAP evidence: {record['name']}")
    print("PASS executed architecture clock units=5")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("configured", "executed"))
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    if args.stage == "configured":
        configured(args.path)
    else:
        executed(args.path)


if __name__ == "__main__":
    main()
