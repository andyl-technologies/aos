# SPDX-License-Identifier: MIT
"""Checks actual PMULL variants against an independent coefficient oracle."""

import json
from pathlib import Path
import struct
import sys

import m5
from m5.objects import (
    AddrRange, ArmAtomicSimpleCPU, Process, Root, SEWorkload, SimpleMemory,
    SrcClockDomain, System, SystemXBar, VoltageDomain,
)


def polynomial_product(left, right, width):
    """Multiplies explicit coefficient sets over GF(2), without carries."""
    first = [index for index in range(width) if left & (1 << index)]
    second = [index for index in range(width) if right & (1 << index)]
    coefficients = [0] * (width * 2)
    for a in first:
        for b in second:
            coefficients[a + b] ^= 1
    return sum(bit << index for index, bit in enumerate(coefficients))


def vectors():
    """Exercises every basis pair plus dense and unequal source halves."""
    mask = (1 << 64) - 1
    for first in range(64):
        for second in range(64):
            yield (1 << first, mask ^ (1 << second),
                   1 << second, mask ^ (1 << first))
    for first, second in [(0, 0), (0, mask), (1, mask), (mask, mask),
                          (0x8000000000000000, 0x8000000000000000),
                          (0x0123456789abcdef, 0xfedcba9876543210)]:
        yield first, first ^ mask, second, second ^ mask
    state = 0x7f4a7c159e3779b9
    for _ in range(256):
        row = []
        for _ in range(4):
            state ^= state << 13
            state ^= state >> 7
            state ^= state << 17
            state &= mask
            row.append(state)
        yield tuple(row)


if len(sys.argv) != 4:
    raise RuntimeError("expected source-built guest ELF, private input and output")
executable, input_path, output_path = sys.argv[1:]
rows = list(vectors())
Path(input_path).write_bytes(b"".join(struct.pack("<4Q", *row) for row in rows))
system = System()
system.clk_domain = SrcClockDomain(clock="1GHz", voltage_domain=VoltageDomain())
system.mem_mode = "atomic"
system.mem_ranges = [AddrRange("128MiB")]
system.cpu = ArmAtomicSimpleCPU()
system.bus = SystemXBar()
system.memory = SimpleMemory(range=system.mem_ranges[0])
system.memory.port = system.bus.mem_side_ports
system.system_port = system.bus.cpu_side_ports
system.cpu.createInterruptController()
system.cpu.connectBus(system.bus)
system.workload = SEWorkload.init_compatible(executable)
system.cpu.workload = Process(executable=executable, cmd=["pmull-probe"],
                              input=input_path, output=output_path)
system.cpu.createThreads()
root = Root(full_system=False, system=system)
m5.instantiate()
result = m5.simulateUntilBoundary(m5.MaxTick, 2000000)
assert result.exitEvent is not None and result.exitEvent.getCode() == 0
observed = Path(output_path).read_bytes()
assert len(observed) == len(rows) * 96
for index, row in enumerate(rows):
    first_low, first_high, second_low, second_high = row
    lower = polynomial_product(first_low, second_low, 64).to_bytes(16, "little")
    upper = polynomial_product(first_high, second_high, 64).to_bytes(16, "little")
    byte_results = []
    for first, second in [(first_low, second_low), (first_high, second_high)]:
        byte_results.append(b"".join(
            polynomial_product((first >> shift) & 255, (second >> shift) & 255, 8)
            .to_bytes(2, "little") for shift in range(0, 64, 8)))
    expected = lower + upper + b"".join(byte_results) + lower + upper
    assert observed[index * 96:(index + 1) * 96] == expected, index
print(json.dumps({
    "schema": "crucible.gem5.aarch64-pmull-mechanism.v1",
    "basisPairs": 4096, "vectorsVerified": len(rows),
    "lowerUpper64BitVerified": True, "byteVariantsPreserved": True,
    "destinationSourceAliasesVerified": True,
    "completeStateQualified": False, "cpuTimingQualified": False,
}, sort_keys=True, separators=(",", ":")))
