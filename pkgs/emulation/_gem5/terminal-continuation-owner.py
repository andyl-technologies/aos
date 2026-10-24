# SPDX-License-Identifier: MIT
"""Parks real Terminal FIFO bytes and a future callback across opaque capture.

This is an isolated native mechanism witness, not a full-system profile owner
or a certificate for complete CPU/device/resource closure.
"""

import ctypes
import json
import os
from pathlib import Path
import sys

import m5
from m5.objects import (
    AddrRange, CrucibleTerminalWitness, Root, SimpleMemory, SrcClockDomain,
    System, SystemXBar, Terminal, VoltageDomain,
)


resource = Path(sys.argv[1])
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
assert system.probe.scheduleWrites(11)
cut = m5.simulateUntilBoundary(12, 1)
assert cut.currentTick == 11 and cut.processedEvents == 1
assert system.probe.scheduleWrites(12)
birth = list(terminal.crucibleOutputMetadata())
position = m5.crucibleEventPosition()
assert birth == [1, 11, 1, 1, 17, 1]
assert bytes(terminal.crucibleOutputBytes()) == b"A"
assert position["active"] is False

native = ctypes.CDLL(None)
checkpoint = native.dmtcp_checkpoint
checkpoint.restype = ctypes.c_int
status = checkpoint()
if status not in (1, 2):
    raise RuntimeError("actual native checkpoint did not capture or reconstruct")
if status == 2:
    restart_env = native.dmtcp_get_restart_env
    restart_env.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
    replacement = ctypes.create_string_buffer(4096)
    if restart_env(b"CRUCIBLE_RESTORE_RESOURCE_ROOT", replacement, len(replacement)) != 0:
        raise RuntimeError("fresh native resource binding omitted")
    resource = Path(os.fsdecode(replacement.value))
    assert resource.is_absolute() and resource.resolve() == resource
    if restart_env(b"CRUCIBLE_GEM5_OPERATIONAL_ROOT", replacement, len(replacement)) != 0:
        raise RuntimeError("fresh native operational binding omitted")
    operational = Path(os.fsdecode(replacement.value))
    assert operational.is_absolute() and operational.resolve() == operational
    os.chdir(operational)

    # Only operational file routing changes at this parked boundary. Native
    # event counters, retained FIFO and queued callback remain untouched.
    native.setenv.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
    native.setenv.restype = ctypes.c_int
    if native.setenv(b"CRUCIBLE_CAPTURE_RESOURCE_ROOT", os.fsencode(resource), 1) != 0:
        raise RuntimeError("native resource-root readback binding failed")

assert list(terminal.crucibleOutputMetadata()) == birth
assert bytes(terminal.crucibleOutputBytes()) == b"A"
assert m5.crucibleEventPosition() == position
parked = m5.simulateUntilBoundary(12, 100)
assert parked.processedEvents == 0 and parked.currentTick == 11
assert m5.crucibleEventPosition() == position
retained = []
for identifier, byte in enumerate(b"A\0B", 1):
    expected = [identifier, 11, 1, 1, 17, 1]
    assert list(terminal.crucibleOutputMetadata()) == expected
    assert bytes(terminal.crucibleOutputBytes()) == bytes([byte])
    assert not terminal.crucibleAcknowledgeOutput(identifier + 1)
    assert list(terminal.crucibleOutputMetadata()) == expected
    retained.append({"birth": expected, "payload": [byte]})
    assert terminal.crucibleAcknowledgeOutput(identifier)
    assert terminal.crucibleAcknowledgeOutput(identifier)

later = m5.simulateUntilBoundary(13, 1)
assert later.processedEvents == 1 and later.currentTick == 12
for identifier, byte in enumerate(b"A\0B", 4):
    expected = [identifier, 12, 2, 1, 17, 1]
    assert list(terminal.crucibleOutputMetadata()) == expected
    assert bytes(terminal.crucibleOutputBytes()) == bytes([byte])
    retained.append({"birth": expected, "payload": [byte]})
    assert terminal.crucibleAcknowledgeOutput(identifier)
assert list(terminal.crucibleOutputMetadata()) == []

result = {"schema": "crucible.gem5.terminal-continuation-mechanism.v1",
          "cut": position, "publications": retained,
          "final_position": m5.crucibleEventPosition(), "full_system_qualified": False}
(resource / "terminal-result.json").write_text(json.dumps(result, sort_keys=True) + "\n")
