# SPDX-License-Identifier: MIT
"""Exercises actual native absent-register request bounds without guest claims."""
import json
import m5
from m5.objects import (
    AbsentFchResetStatus, AbsentFchResetStatusWitness, AddrRange, Root,
    SimpleMemory, SrcClockDomain, System, SystemXBar, VoltageDomain,
)

system = System()
system.mem_mode = "atomic"
system.clk_domain = SrcClockDomain(clock="100MHz", voltage_domain=VoltageDomain())
system.mem_ranges = [AddrRange("128KiB")]
system.bus = SystemXBar()
system.memory = SimpleMemory(range=system.mem_ranges[0])
system.memory.port = system.bus.mem_side_ports
system.system_port = system.bus.cpu_side_ports
system.optional_reset_status = AbsentFchResetStatus()
system.optional_reset_status.pio = system.bus.mem_side_ports
system.witness = AbsentFchResetStatusWitness(device=system.optional_reset_status)
root = Root(full_system=False, system=system)
m5.instantiate()
before = m5.simulateUntilBoundary(1, 0)
assert system.witness.run() == 10
assert system.witness.run() == 10
assert bytes(system.physProxy.read(0xfed803c0, 4)) == bytes([255] * 4)
after = m5.simulateUntilBoundary(1, 0)
assert before.currentTick == after.currentTick
assert before.nextTick == after.nextTick and after.processedEvents == 0
print(json.dumps({
    "schema": "crucible.gem5.absent-fch-reset-status-mechanism.v1",
    "nativeCases": 10, "unchangedRepeatVerified": True,
    "actualBusReadVerified": True, "exactAddressWidthVerified": True,
    "invalidWritesRefused": True, "absenceErrorResponse": "4294967295",
    "fullSystemQualified": False,
}, sort_keys=True, separators=(",", ":")))
