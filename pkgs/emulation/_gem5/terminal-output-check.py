# SPDX-License-Identifier: MIT
"""Exercises actual Terminal publication birth and stopped original custody.

This native mechanism fixture qualifies neither a full-system image nor a
Linux readiness cut. Its writes are actual event callbacks to Terminal.
"""

import json

import m5
from m5.objects import (
    AddrRange, CrucibleTerminalWitness, Root, SimpleMemory, SrcClockDomain,
    System, SystemXBar, Terminal, VoltageDomain,
)


system = System(mem_mode="atomic")
system.clk_domain = SrcClockDomain(clock="100MHz", voltage_domain=VoltageDomain())
system.mem_ranges = [AddrRange("128KiB")]
system.bus = SystemXBar()
system.memory = SimpleMemory(range=system.mem_ranges[0])
system.memory.port = system.bus.mem_side_ports
system.system_port = system.bus.cpu_side_ports
system.terminal = Terminal(port=0, outfile="none")
system.probe = CrucibleTerminalWitness(terminal=system.terminal)
root = Root(full_system=False, system=system)
m5.instantiate()
terminal = system.terminal
terminal.crucibleConfigureOutput()
assert terminal.crucibleSetOutputParent(17)
assert not terminal.crucibleAcknowledgeOutput(0)
assert list(terminal.crucibleOutputMetadata()) == []
assert bytes(terminal.crucibleOutputBytes()) == b""
assert not system.probe.scheduleWrites(0)
assert system.probe.scheduleWrites(11)
assert not system.probe.scheduleWrites(12)

before = m5.simulateUntilBoundary(11, 8)
assert before.currentTick < 11 and before.processedEvents == 0
assert list(terminal.crucibleOutputMetadata()) == []
cut = m5.simulateUntilBoundary(12, 1)
assert cut.currentTick == 11 and cut.processedEvents == 1
position = m5.crucibleEventPosition()
assert position["tick"] == "11" and position["active"] is False
births = []
for identifier, byte in enumerate(b"A\0B", 1):
    original = list(terminal.crucibleOutputMetadata())
    assert original == [identifier, 11, int(position["ordinal"]),
                        int(position["tick_ordinal"]), 17, 1]
    assert bytes(terminal.crucibleOutputBytes()) == bytes([byte])
    assert list(terminal.crucibleOutputMetadata()) == original
    assert not terminal.crucibleSetOutputParent(23)
    assert not terminal.crucibleAcknowledgeOutput(identifier + 1)
    assert list(terminal.crucibleOutputMetadata()) == original
    parked = m5.simulateUntilBoundary(12, 0)
    assert parked.processedEvents == 0 and parked.currentTick == 11
    assert terminal.crucibleAcknowledgeOutput(identifier)
    assert terminal.crucibleAcknowledgeOutput(identifier)
    births.append(original)

assert list(terminal.crucibleOutputMetadata()) == []
assert terminal.crucibleSetOutputParent(23)
assert system.probe.scheduleWrites(12)
later = m5.simulateUntilBoundary(13, 1)
assert later.currentTick == 12 and later.processedEvents == 1
assert list(terminal.crucibleOutputMetadata()) == [4, 12, int(position["ordinal"]) + 1, 1, 23, 1]
for identifier in range(4, 7):
    assert terminal.crucibleAcknowledgeOutput(identifier)

print(json.dumps({
    "schema": "crucible.gem5.terminal-publication-mechanism.v1",
    "actualCallbackBirth": True,
    "exclusiveStopBeforeBirth": True,
    "sameCallbackDistinctOriginalIds": True,
    "immutableUntilOriginalAck": True,
    "wrongAckPreservesCustody": True,
    "embeddedNulPreserved": True,
    "observationDoesNotServiceEvents": True,
    "fullSystemQualified": False,
    "births": births,
}, sort_keys=True, separators=(",", ":")))
