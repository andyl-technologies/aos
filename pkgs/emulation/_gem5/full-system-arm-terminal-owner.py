# SPDX-License-Identifier: MIT
"""Captures an actual ARM Linux serial birth without draining modeled devices.

The model matches the existing functional ARM Linux fixture. This witness
compares original native FIFO/event continuations; full-system closure, driver
readiness and CPU timing admission remain separately unqualified.
"""

import ctypes
import hashlib
import json
import os
from pathlib import Path
import sys

import m5
from m5.objects import (
    ArmAtomicSimpleCPU, Root, SimpleMemory, SrcClockDomain, VoltageDomain,
)


resource, configs, kernel, initrd, bootloader = sys.argv[1:]
resource = Path(resource)
sys.path.insert(0, configs)
from common.Benchmarks import SysConfig
from common.FSConfig import makeArmSystem

system = makeArmSystem(
    "atomic", "VExpress_GEM5_V2", num_cpus=1,
    mdesc=SysConfig(mem="256MiB", disks=[]), bootloader=[bootloader],
    cmdline="console=ttyAMA0 earlycon=pl011,0x1c090000 rdinit=/init panic=1 "
            "lpj=1000000 init_on_alloc=0 init_on_free=0 nokaslr net.ifnames=0",
)
system.voltage_domain = VoltageDomain()
system.clk_domain = SrcClockDomain(clock="100MHz", voltage_domain=system.voltage_domain)
system.workload.object_file = kernel
system.workload.initrd_filename = initrd
system.cpu = ArmAtomicSimpleCPU(cpu_id=0, width=16)
system.cpu.createThreads()
system.cpu.createInterruptController()
system.cpu.connectBus(system.membus)
system.memory = SimpleMemory(range=system.mem_ranges[0])
system.memory.port = system.membus.mem_side_ports
system.terminal.port = 0
system.terminal.outfile = "none"
root = Root(full_system=True, system=system)
system.generateDtb(str(resource / "output" / "fixture.dtb"))
system.workload.dtb_filename = str(resource / "output" / "fixture.dtb")
m5.instantiate()
terminal = system.terminal
terminal.crucibleConfigureOutput()
assert terminal.crucibleSetOutputParent(17)

for events in range(500000):
    result = m5.simulateUntilBoundary(100000000000, 1)
    if list(terminal.crucibleOutputMetadata()):
        break
    if result.processedEvents == 0:
        raise RuntimeError("no actual ARM Linux serial birth before native horizon")
else:
    raise RuntimeError("actual ARM Linux serial birth exhausted finite event credit")
birth = list(terminal.crucibleOutputMetadata())
payload = bytes(terminal.crucibleOutputBytes())
position = m5.crucibleEventPosition()
assert birth[0] == 1 and birth[1] == int(position["tick"])
assert birth[2] == int(position["ordinal"]) and birth[3] == int(position["tick_ordinal"])
assert birth[4:] == [17, 1] and len(payload) == 1 and position["active"] is False

native = ctypes.CDLL(None)
checkpoint = native.dmtcp_checkpoint
checkpoint.restype = ctypes.c_int
status = checkpoint()
if status not in (1, 2):
    raise RuntimeError("actual native image capture failed")
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
    native.setenv.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
    native.setenv.restype = ctypes.c_int
    if native.setenv(b"CRUCIBLE_CAPTURE_RESOURCE_ROOT", os.fsencode(resource), 1) != 0:
        raise RuntimeError("native resource rebind failed")

assert list(terminal.crucibleOutputMetadata()) == birth
assert bytes(terminal.crucibleOutputBytes()) == payload
assert m5.crucibleEventPosition() == position
parked = m5.simulateUntilBoundary(int(position["tick"]), 100)
assert parked.processedEvents == 0 and m5.crucibleEventPosition() == position
retained = []


def consume_original_bytes():
    while True:
        metadata = list(terminal.crucibleOutputMetadata())
        if not metadata:
            return
        original = bytes(terminal.crucibleOutputBytes())
        assert metadata[4:] == [17, 1] and len(original) == 1
        assert not terminal.crucibleAcknowledgeOutput(metadata[0] + 1)
        assert list(terminal.crucibleOutputMetadata()) == metadata
        retained.append({"birth": metadata, "payload": list(original)})
        assert terminal.crucibleAcknowledgeOutput(metadata[0])
        assert terminal.crucibleAcknowledgeOutput(metadata[0])


consume_original_bytes()
for events in range(5000):
    result = m5.simulateUntilBoundary(100000000000, 1)
    if result.processedEvents != 1:
        raise RuntimeError("bounded native Linux suffix failed to service one callback")
    consume_original_bytes()
bindings = {}
for name, path in (("kernel", kernel), ("initramfs", initrd), ("firmware", bootloader)):
    with Path(path).open("rb") as stream:
        bindings[name] = {"path": path, "sha256": hashlib.file_digest(stream, "sha256").hexdigest(),
                          "length": str(Path(path).stat().st_size)}
result = {"schema": "crucible.gem5.arm-linux-terminal-continuation-mechanism.v1",
          "cut": position, "publications": retained,
          "final_position": m5.crucibleEventPosition(), "suffix_callbacks": "5000",
          "guest_assets": bindings, "full_system_qualified": False,
          "linux_readiness_qualified": False, "cpu_timing_qualified": False}
(resource / "terminal-result.json").write_text(json.dumps(result, sort_keys=True) + "\n")
