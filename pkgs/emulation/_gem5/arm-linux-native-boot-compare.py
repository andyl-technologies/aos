# SPDX-License-Identifier: MIT
"""Compares two fresh native Linux boot observations, without capture authority."""

import hashlib
import json
from pathlib import Path
import sys


MAX_DOCUMENT = 4 * 1024 * 1024
MAX_CONSOLE = 256 * 1024
REQUIRED_LINES = ["GEM5_LINUX_INIT_READY", "GEM5_LINUX_PROBE_COMPLETE"]
UNQUALIFIED = ["common_node_ready_qualified", "capture_qualified",
               "restored_continuation_qualified", "device_parity_qualified",
               "cpu_timing_qualified"]


def read_observation(receipt_path, console_path):
    """Authenticates bounded local observation bytes before comparing them."""
    with Path(receipt_path).open("rb") as stream:
        encoded = stream.read(MAX_DOCUMENT + 1)
    if not 0 < len(encoded) <= MAX_DOCUMENT:
        raise ValueError("boot receipt exceeds its finite extent")
    receipt = json.loads(encoded)
    if (type(receipt) is not dict
            or set(receipt) != {"schema", "model_id", "tick", "processed_events",
                               "limits", "required_lines", "console",
                               "installed_artifacts", "configuration_binding", *UNQUALIFIED}
            or receipt.get("schema") != "crucible.gem5.arm-linux-pid1-boot-check.v1"
            or receipt.get("model_id") != "arm-linux-vexpress-atomic-functional-v1"
            or receipt.get("required_lines") != REQUIRED_LINES
            or any(receipt.get(field) is not False for field in UNQUALIFIED)):
        raise ValueError("boot observation has a foreign model or authority claim")
    with Path(console_path).open("rb") as stream:
        console = stream.read(MAX_CONSOLE + 1)
    if (not 0 < len(console) <= MAX_CONSOLE
            or receipt["console"]["bytes"] != len(console)
            or receipt["console"]["sha256"] != hashlib.sha256(console).hexdigest()):
        raise ValueError("original console bytes differ from their boot receipt")
    lines = console.splitlines()
    if any(line.encode("ascii") not in lines for line in REQUIRED_LINES):
        raise ValueError("original console lacks both complete PID1 lines")
    return receipt, hashlib.sha256(encoded).hexdigest()


def compare(left, right):
    """Requires identical raw console, callback births, native clock and inputs."""
    for field in ("schema", "model_id", "tick", "processed_events", "limits",
                  "required_lines", "console", "installed_artifacts",
                  "configuration_binding", *UNQUALIFIED):
        if left[field] != right[field]:
            raise ValueError("fresh native boot observations differ: " + field)


def main():
    if len(sys.argv) != 6:
        raise ValueError("expected receipt1 console1 receipt2 console2 output")
    first, first_hash = read_observation(sys.argv[1], sys.argv[2])
    second, second_hash = read_observation(sys.argv[3], sys.argv[4])
    compare(first, second)
    result = {
        "schema": "crucible.gem5.arm-linux-two-fresh-boots.v1",
        "observation_count": 2,
        "receipt_sha256": [first_hash, second_hash],
        "tick": first["tick"],
        "processed_events": first["processed_events"],
        "console_bytes": first["console"]["bytes"],
        "console_sha256": first["console"]["sha256"],
        "native_birth_sha256": first["console"]["birth_sha256"],
        "scope": "Two fresh executions reproduced these specific boot observations; "
                 "this does not qualify general CPU timing, source authority, "
                 "device parity, capture or restored continuation.",
    }
    encoded = json.dumps(result, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    if len(encoded) > MAX_DOCUMENT:
        raise ValueError("fresh boot comparison exceeds its finite output extent")
    with Path(sys.argv[5]).open("xb") as stream:
        stream.write(encoded)


if __name__ == "__main__":
    main()
