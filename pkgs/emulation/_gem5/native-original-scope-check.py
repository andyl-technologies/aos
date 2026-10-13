# SPDX-License-Identifier: MIT
"""Checks actual diagnostic graph ownership without issuing a native permit."""

import hashlib
import json
import os
import signal
import sys
import time
from pathlib import Path

import m5
import _m5.event as native_event
from m5.objects import (
    AddrRange,
    ArmAtomicSimpleCPU,
    CrucibleAtomicFabric,
    CrucibleClosedScriptBlock,
    Process,
    Root,
    SEWorkload,
    SimpleMemory,
    SrcClockDomain,
    System,
    SystemXBar,
    VoltageDomain,
)


if len(sys.argv) != 3 or sys.argv[2] not in (
    "owned", "unknown-bus", "changed-clock", "foreign-helper", "unarmed"
):
    raise ValueError("expected diagnostic fixed-loop ELF and native control mode")

program = str(Path(sys.argv[1]).resolve(strict=True))
mode = sys.argv[2]
source_stat = Path("/proc/self/stat").read_text()
generation = int(source_stat.rsplit(") ", 1)[1].split()[19])
profile = native_event.crucibleDiagnosticOriginalProfile()
scope = hashlib.sha256(b"diagnostic-original-scope-v1").digest()
setup = hashlib.sha256(Path(__file__).read_bytes()).digest()
implementation = hashlib.sha256(Path("/proc/self/exe").read_bytes()).digest()
plan = hashlib.sha256(b"diagnostic-owner-walk-only;runtime-refused").digest()
# The native Digest caster accepts integer sequences and deliberately rejects
# Python bytes. Preserve every digest byte while crossing that typed boundary.
digest_fields = tuple(list(value) for value in (scope, setup, profile, implementation, plan))
assert native_event.crucibleSelectDiagnosticOriginalScope(
    *digest_fields, 1, generation
)

# Selection consumes the original storage reservation before validation. A
# second call cannot replace the original account or renew a refused attempt.
assert not native_event.crucibleSelectDiagnosticOriginalScope(
    *digest_fields, 1, generation
)

m5.ticks.setGlobalFrequency("1THz")
m5.core.disableAllListeners()
system = System()
system.clk_domain = SrcClockDomain(
    clock="2GHz" if mode == "changed-clock" else "1GHz",
    voltage_domain=VoltageDomain(),
)
system.mem_mode = "atomic"
system.mem_ranges = [AddrRange("16MiB")]
system.cpu = ArmAtomicSimpleCPU(cpu_id=0, width=1)
system.bus = SystemXBar() if mode == "unknown-bus" else CrucibleAtomicFabric()
system.memory = SimpleMemory(range=system.mem_ranges[0])
if mode == "unknown-bus":
    system.memory.port = system.bus.mem_side_ports
else:
    system.memory.port = system.bus.mem_side_port
system.system_port = system.bus.cpu_side_ports
system.cpu.icache_port = system.bus.cpu_side_ports
system.cpu.dcache_port = system.bus.cpu_side_ports
system.cpu.createInterruptController()
system.cpu.workload = Process(cmd=[program])
system.workload = SEWorkload.init_compatible(program)
system.workload.remote_gdb_port = 0
system.cpu.createThreads()
system.block = CrucibleClosedScriptBlock()
root = Root(full_system=False, system=system)
m5.instantiate()

# Startup establishes the original CPU/member callbacks but the exclusive
# zero boundary services none. There is no drain, capture, or guest effect.
boundary = m5.simulateUntilBoundary(0, 1)
assert boundary.processedEvents == 0
before = m5.crucibleEventPosition()
inspection = native_event.crucibleInspectDiagnosticOriginalOwnership()
after = m5.crucibleEventPosition()
# Retain the actual native refusal code and graph counts before an assertion
# can terminate this process; the package publishes the original log on failure.
print(json.dumps({
    "schema": "crucible.gem5.diagnostic-original-native-inspection.v1",
    "mode": mode,
    "ownership": list(inspection),
    "queue_before": dict(before),
    "queue_after": dict(after),
}, sort_keys=True, separators=(",", ":")), flush=True)
assert before == after
assert inspection[0] == (mode in ("owned", "foreign-helper", "unarmed"))

if mode == "foreign-helper":
    child = os.fork()
    if child == 0:
        # Invoke the actual public C++ helper directly, bypassing private
        # walk() so its intrinsic guard is the cause of this refusal.
        native_event.crucibleDiagnosticDirectQueueOwnership()
        os._exit(124)

    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        finished, status = os.waitpid(child, os.WNOHANG)
        if finished:
            break
        time.sleep(0.002)
    else:
        os.kill(child, signal.SIGKILL)
        os.waitpid(child, 0)
        raise RuntimeError("foreign helper did not terminate within its budget")
    assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 125
    assert m5.crucibleEventPosition() == after

print(json.dumps({
    "schema": "crucible.gem5.diagnostic-original-native-ownership.v1",
    "mode": mode,
    "ownership": list(inspection),
    "native_tick": str(m5.curTick()),
    "native_source_cut_qualified": False,
    "native_restore_qualified": False,
    "linux_qualified": False,
    "general_isa_qualified": False,
    "device_parity_qualified": False,
    "common_ready_qualified": False,
}, sort_keys=True, separators=(",", ":")), flush=True)

if mode == "unarmed":
    # A successful source graph inspection cannot authorize even the exact
    # diagnostic instruction. The native guard must terminate with exit126.
    m5.simulateUntilBoundary(1, 1)
    raise RuntimeError("ownership-only inspection unexpectedly armed execution")
