# SPDX-License-Identifier: MIT
"""Checks actual CPUID subleaf bounds without claiming CPU qualification.

The guest observes both configured tuples, four unsupported indices (including
multiplication overflow cases), and an unchanged non-indexed leaf. Its binary
output comes from the real instruction executor, not a parser or mock CPUID map.
"""

import json
from pathlib import Path
import struct
import sys

import m5
from m5.objects import (
    AddrRange, Process, Root, SEWorkload, SimpleMemory, SrcClockDomain, System,
    SystemXBar, VoltageDomain, X86AtomicSimpleCPU, X86ISA,
)

if len(sys.argv) != 3:
    raise RuntimeError("expected source-built guest ELF and private output path")

executable, output = sys.argv[1:]
system = System()
system.clk_domain = SrcClockDomain(clock="1GHz", voltage_domain=VoltageDomain())
system.mem_mode = "atomic"
system.mem_ranges = [AddrRange("128MiB")]
system.cpu = X86AtomicSimpleCPU(isa=[X86ISA(ExtendedState=[
    0x11, 0x22, 0x33, 0x44,
    0x55, 0x66, 0x77, 0x88,
])])
system.bus = SystemXBar()
system.memory = SimpleMemory(range=system.mem_ranges[0])
system.memory.port = system.bus.mem_side_ports
system.system_port = system.bus.cpu_side_ports
system.cpu.createInterruptController()
system.cpu.connectBus(system.bus)
system.workload = SEWorkload.init_compatible(executable)
system.cpu.workload = Process(executable=executable, cmd=["cpuid-subleaf-probe"], output=output)
system.cpu.createThreads()
root = Root(full_system=False, system=system)
m5.instantiate()

result = m5.simulateUntilBoundary(m5.MaxTick, 4096)
assert result.exitEvent is not None, "bounded native guest never exited"
assert result.exitEvent.getCode() == 0
observed = Path(output).read_bytes()
expected = struct.pack("<32I",
    0x11, 0x22, 0x44, 0x33,
    0x55, 0x66, 0x88, 0x77,
    *([0] * 16),
    0x00020f51, 0x00000805, 0x00000209, 0xefdbfbff,
    0x00020f51, 0x00000805, 0x00000209, 0xefdbfbff,
)
assert observed == expected, f"native CPUID register output mismatch: {observed.hex()}"

print(json.dumps({
    "schema": "crucible.gem5.x86-cpuid-subleaf-mechanism.v1",
    "configuredRowsPreserved": 2,
    "unsupportedIndicesVerified": [2, 63, 0x40000000, 0xffffffff],
    "nonIndexedLeafPreserved": True,
    "actualGuestBytes": len(observed),
    "processedEvents": str(result.processedEvents),
    "cpuTimingQualified": False,
    "completeStateQualified": False,
}, sort_keys=True, separators=(",", ":")))
