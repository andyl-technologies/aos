# SPDX-License-Identifier: MIT
"""Exercises O3/cache/DRAM continuation; not complete microstate qualification."""

import ctypes
import importlib.util
import json
import os
import hashlib
from pathlib import Path
import sys

import m5
from m5.objects import (
    AddrRange,
    ArmO3CPU,
    Cache,
    DDR3_1600_8x8,
    L2XBar,
    MemCtrl,
    Process,
    RandomRP,
    Root,
    SEWorkload,
    SrcClockDomain,
    System,
    SystemXBar,
    VoltageDomain,
    X86O3CPU,
)


guest_isa, mode, executable, prefix, coverage_helper, memory_helper = sys.argv[1:]
helper_spec = importlib.util.spec_from_file_location("cpu_state_coverage", coverage_helper)
coverage = importlib.util.module_from_spec(helper_spec)
helper_spec.loader.exec_module(coverage)
memory_spec = importlib.util.spec_from_file_location("memory_state_coverage", memory_helper)
memory_coverage = importlib.util.module_from_spec(memory_spec)
memory_spec.loader.exec_module(memory_coverage)
if guest_isa not in ("x86_64", "aarch64"):
    raise ValueError(guest_isa)
m5.core.disableAllListeners()
system = System()
system.clk_domain = SrcClockDomain(clock="1GHz", voltage_domain=VoltageDomain())
system.mem_mode = "timing"
system.mem_ranges = [AddrRange("512MiB")]
system.cpu = X86O3CPU() if guest_isa == "x86_64" else ArmO3CPU()
system.cpu.icache = Cache(
    size="32KiB", assoc=2, tag_latency=2, data_latency=2, response_latency=2,
    mshrs=8, tgts_per_mshr=8,
)
system.cpu.dcache = Cache(
    size="32KiB", assoc=2, tag_latency=2, data_latency=2, response_latency=2,
    mshrs=16, tgts_per_mshr=8,
    replacement_policy=RandomRP(),
)
system.l2bus = L2XBar()
system.l2 = Cache(
    size="256KiB", assoc=8, tag_latency=12, data_latency=12, response_latency=12,
    mshrs=32, tgts_per_mshr=8,
)
system.membus = SystemXBar()
system.cpu.icache.cpu_side = system.cpu.icache_port
system.cpu.dcache.cpu_side = system.cpu.dcache_port
system.cpu.icache.mem_side = system.l2bus.cpu_side_ports
system.cpu.dcache.mem_side = system.l2bus.cpu_side_ports
system.l2.cpu_side = system.l2bus.mem_side_ports
system.l2.mem_side = system.membus.cpu_side_ports
system.cpu.createInterruptController()
if guest_isa == "x86_64":
    system.cpu.interrupts[0].pio = system.membus.mem_side_ports
    system.cpu.interrupts[0].int_requestor = system.membus.cpu_side_ports
    system.cpu.interrupts[0].int_responder = system.membus.mem_side_ports
system.cpu.mmu.connectWalkerPorts(
    system.membus.cpu_side_ports, system.membus.cpu_side_ports
)
system.system_port = system.membus.cpu_side_ports
system.mem_ctrl = MemCtrl(dram=DDR3_1600_8x8())
system.mem_ctrl.dram.range = system.mem_ranges[0]
system.mem_ctrl.port = system.membus.mem_side_ports
system.workload = SEWorkload.init_compatible(executable)
process = Process(
    executable=executable,
    cmd=["crucible-o3-workload"],
    output=f"{prefix}.guest",
)
system.cpu.workload = process
system.cpu.createThreads()
root = Root(full_system=False, system=system)
m5.instantiate()

# Diagnostics begin at the same execution prefix in all controls. No stock
# simulate(limit), checkpoint, drain, fork or cache writeback path is used.
cut = m5.simulateUntilBoundary(m5.MaxTick, 5000)
assert cut.processedEvents == 5000 and cut.exitEvent is None
assert cut.hasNextEvent
boundary = (cut.currentTick, cut.nextTick, cut.nextPriority)
m5.stats.dump()
inventory = m5.crucibleStateInventory()
assert inventory == m5.crucibleStateInventory()
assert inventory["native_tick"] == str(cut.currentTick)
assert inventory["complete"] is False and inventory["unsupported_domains"]
assert any(not engine["expired"] for engine in inventory["rng"]["engines"])
assert coverage.inspect_instruction_inventory(inventory, guest_isa)
assert memory_coverage.inspect_inventory(inventory, 512 * 1024 * 1024)
assert memory_coverage.inspect_packet_payloads(inventory)
try:
    memory_coverage.require_complete_inventory(inventory, 512 * 1024 * 1024)
except ValueError:
    pass
else:
    raise AssertionError("partial native memory fields admitted as complete state")
try:
    coverage.require_complete_inventory(inventory, guest_isa)
except ValueError:
    pass
else:
    raise AssertionError("partial native fields admitted as complete state")

if os.environ.get("CRUCIBLE_GEM5_DUMP_INVENTORY"):
    Path(f"{prefix}.inventory.json").write_text(json.dumps(inventory, sort_keys=True))

status = 1
if mode == "capture":
    library = ctypes.CDLL(None)
    assert library.dmtcp_get_ckpt_signal() == 40
    checkpoint = library.dmtcp_checkpoint
    checkpoint.argtypes = []
    checkpoint.restype = ctypes.c_int
    status = checkpoint()
    if status not in (1, 2):
        raise RuntimeError(f"DMTCP checkpoint failed: {status}")
    assert m5.crucibleStateInventory() == inventory
elif mode != "baseline":
    raise ValueError(mode)

unchanged = m5.simulateUntilBoundary(m5.MaxTick, 0)
assert (unchanged.currentTick, unchanged.nextTick, unchanged.nextPriority) == boundary
m5.debug.flags["Event"].enable()
result = m5.simulateUntilBoundary(m5.MaxTick, 10000000)
assert result.exitEvent is not None
assert result.exitEvent.getCode() == 0
summary = {
    "guestIsa": guest_isa,
    "partialInventorySha256": hashlib.sha256(
        json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest(),
    "boundary": boundary,
    "futureEvents": result.processedEvents,
    "finalTick": result.currentTick,
    "cause": result.exitEvent.getCause(),
    "code": result.exitEvent.getCode(),
}
suffix = "restored" if status == 2 else "original"
Path(f"{prefix}.{suffix}").write_text(json.dumps(summary, sort_keys=True) + "\n")
