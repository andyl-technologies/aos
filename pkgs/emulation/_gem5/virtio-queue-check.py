# SPDX-License-Identifier: MIT
"""Checks actual native split-ring processing without claiming device parity."""

import json
import sys

import m5
from m5.objects import (
    AddrRange,
    Root,
    SimpleMemory,
    SrcClockDomain,
    System,
    SystemXBar,
    VirtIOQueueWitness,
    VoltageDomain,
)

if len(sys.argv) != 2:
    raise RuntimeError("expected one native queue probe name")

mode = sys.argv[1]
system = System()
system.clk_domain = SrcClockDomain(
    clock="1GHz", voltage_domain=VoltageDomain()
)
system.mem_mode = "atomic"
system.mem_ranges = [AddrRange("128KiB")]
system.bus = SystemXBar()
system.memory = SimpleMemory(range=system.mem_ranges[0])
system.memory.port = system.bus.mem_side_ports
system.system_port = system.bus.cpu_side_ports
system.witness = VirtIOQueueWitness()
root = Root(full_system=False, system=system)
m5.instantiate()

# The native probe reads and writes actual guest RAM through System.physProxy;
# invalid queue states terminate inside the same native implementation.
observed = list(system.witness.run(mode))
if mode not in ("modern", "legacy", "guest-used-index"):
    raise AssertionError("invalid native queue state was accepted")

expected = [22, 1, 1, 0, 8 if mode == "legacy" else 2, 1]
if observed != expected:
    raise AssertionError(f"native split-ring result differs: {observed!r}")

print(
    json.dumps(
        {
            "schema": "crucible.gem5.virtio-queue-mechanism.v1",
            "mode": mode,
            "observed": observed,
            "guestBootVerified": False,
            "deviceParityQualified": False,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
)
