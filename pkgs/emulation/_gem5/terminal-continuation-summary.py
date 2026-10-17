# SPDX-License-Identifier: MIT
"""Keeps compact actual continuation commitments rather than raw evidence."""

import hashlib
import json
from pathlib import Path
import sys


source, destination = map(Path, sys.argv[1:])
if source.stat().st_size > 8 * 1024**2:
    raise ValueError("native Terminal receipt exceeds finite metadata credit")
value = json.loads(source.read_bytes())
assert value["schema"] == "crucible.gem5.terminal-image-mechanism.v1"
assert value["source_exited"] and value["original_namespace_absent"]
assert value["full_system_qualified"] is False
assert value["complete_process_closure_qualified"] is False
assert len(value["branches"]) == 2
assert {branch["name"] for branch in value["branches"]} == {"child-a", "child-b"}
assert all(branch["held_fifo_and_future_event_unchanged"] and branch["original_namespace_absent"]
           for branch in value["branches"])
terminal = value["terminal"]
assert terminal["schema"] == "crucible.gem5.arm-linux-terminal-continuation-mechanism.v1"
assert terminal["full_system_qualified"] is False
assert terminal["linux_readiness_qualified"] is False
assert terminal["cpu_timing_qualified"] is False
records = terminal["publications"]
assert 0 < len(records) <= 65536
assert all(record["birth"][0] == index + 1 and record["birth"][4:] == [17, 1]
           and len(record["payload"]) == 1 for index, record in enumerate(records))
console = bytes(record["payload"][0] for record in records)
assert b"Booting Linux" in console and b"bootconsole [pl11] enabled" in console
encoded = json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
summary = {key: value[key] for key in ("schema", "source_exited", "original_namespace_absent",
                                     "image_sha256", "branches", "full_system_qualified",
                                     "complete_process_closure_qualified")}
summary["terminal"] = {key: terminal[key] for key in (
    "schema", "cut", "final_position", "suffix_callbacks", "guest_assets",
    "full_system_qualified", "linux_readiness_qualified", "cpu_timing_qualified")}
summary["terminal"].update({"publications": str(len(records)),
                            "publication_records_sha256": hashlib.sha256(encoded).hexdigest(),
                            "console_sha256": hashlib.sha256(console).hexdigest()})
destination.write_text(json.dumps(summary, sort_keys=True, separators=(",", ":")) + "\n")
