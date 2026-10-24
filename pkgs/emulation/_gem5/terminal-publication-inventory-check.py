# SPDX-License-Identifier: MIT
"""Checks stopped full-FIFO observation of a genuine multi-byte callback."""

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
assert list(terminal.crucibleOutputInventory()) == []
assert system.probe.scheduleWrites(11)
before = m5.simulateUntilBoundary(11, 8)
assert before.processedEvents == 0
assert list(terminal.crucibleOutputInventory()) == []

cut = m5.simulateUntilBoundary(12, 1)
assert cut.processedEvents == 1 and cut.currentTick == 11
position = m5.crucibleEventPosition()
expected = [[identifier, 11, 1, 1, 17, byte]
            for identifier, byte in enumerate(b"A\0B", 1)]
observed = [list(record) for record in terminal.crucibleOutputInventory()]
assert observed == expected
assert [list(record) for record in terminal.crucibleOutputInventory()] == expected
assert m5.crucibleEventPosition() == position
assert not terminal.crucibleAcknowledgeOutput(3)
assert [list(record) for record in terminal.crucibleOutputInventory()] == expected

for index, record in enumerate(expected):
    assert list(terminal.crucibleOutputMetadata()) == record[:-1] + [1]
    assert bytes(terminal.crucibleOutputBytes()) == bytes([record[-1]])
    assert terminal.crucibleAcknowledgeOutput(record[0])
    assert terminal.crucibleAcknowledgeOutput(record[0])
    assert [list(item) for item in terminal.crucibleOutputInventory()] == expected[index + 1:]
    assert m5.crucibleEventPosition() == position

assert list(terminal.crucibleOutputInventory()) == []
assert terminal.crucibleSetOutputParent(23)
print(json.dumps({
    "schema": "crucible.gem5.terminal-publication-inventory-mechanism.v1",
    "full_fifo_unchanged_until_original_ack": True,
    "all_same_callback_bytes_present": True,
    "exclusive_stop_before_birth": True,
    "observation_preserves_native_position": True,
    "full_system_qualified": False,
    "publications": observed,
}, sort_keys=True, separators=(",", ":")))
