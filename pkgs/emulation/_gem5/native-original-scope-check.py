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
    SystemCounter,
    VoltageDomain,
)


if len(sys.argv) != 3 or sys.argv[2] not in (
    "owned", "unknown-bus", "changed-clock", "foreign-helper", "unarmed",
    "counter-owned", "counter-pending", "counter-invalid-table",
    "counter-copy-original", "counter-copy-foreign", "counter-owner-foreign",
    "counter-callable-foreign", "counter-callable-empty"
):
    raise ValueError("expected diagnostic fixed-loop ELF and native control mode")

program = str(Path(sys.argv[1]).resolve(strict=True))
mode = sys.argv[2]
source_stat = Path("/proc/self/stat").read_text()
generation = int(source_stat.rsplit(") ", 1)[1].split()[19])
profile = native_event.crucibleDiagnosticOriginalProfile()
# Profile v5 checks the actual named counter callable and immutable owner.
# Ordinary heap/control-block closure and execution authority remain separate.
selected_profile_bytes = (
    b'crucible.gem5.diagnostic.arm-atomic-loop.counter-named-callback-owner.v5\x00'
    b'objects=256;edges=4096;callbacks=256;ports=256;tables=16;'
    b'table-entries=1280;lru-constructor-births=1472;'
    b'arm-tlb-entries=64,64,1280,32,32;clock-period-ps=1000;'
    b'counter-frequency-entries=1004;counter-capacity-entries=2008;'
    b'counter-listeners=0;counter-frequency-callback=named-owner-v1;'
    b'callback-mutation=diagnostic-before-walk-only;runtime=refused'
)
assert bytes(profile) == hashlib.sha256(selected_profile_bytes).digest()
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
if mode.startswith("counter-"):
    frequencies = [1000000000, 0 if mode == "counter-invalid-table" else 500000000]
    system.counter = SystemCounter(freqs=frequencies)
if mode in ("counter-copy-foreign", "counter-owner-foreign"):
    system.counter_peer = SystemCounter(freqs=[1000000000, 500000000])
root = Root(full_system=False, system=system)
m5.instantiate()
mutations = {
    "counter-copy-original": 0, "counter-copy-foreign": 1,
    "counter-owner-foreign": 2, "counter-callable-foreign": 3,
    "counter-callable-empty": 4,
}
if mode in mutations:
    other = (system.counter_peer if mode in ("counter-copy-foreign", "counter-owner-foreign")
             else system.counter)
    assert not system.counter.crucibleDiagnosticFrequencyMutation(99, other.getCCObject())
    # This intentional native mutation precedes the inspected cut. It is not
    # described as NoEffects, capture authority or unchanged Event-base state.
    assert system.counter.crucibleDiagnosticFrequencyMutation(mutations[mode], other.getCCObject())
if mode == "counter-pending":
    # This is the actual native hardware frequency-change path. Its tick-zero
    # event remains queued under the exclusive zero boundary below.
    system.counter.freqUpdateSchedule(1)


def counter_inventory():
    """Reads the existing partial selected-object producer without normalizing it."""
    inventory = m5.crucibleDeviceStateInventory(["system.counter"])
    assert inventory["complete"] is False
    assert len(inventory["objects"]) == 1
    record = inventory["objects"][0]
    assert record["name"] == "system.counter" and record["state_complete"] is False
    fields = record["modeled_fields"]
    assert fields["counter.cached_value"] == "0"
    assert fields["counter.update_tick"] == "0"
    assert fields["counter.frequency"] == "1000000000"
    assert fields["counter.period"] == "1000"
    type_matches = mode not in ("counter-callable-foreign", "counter-callable-empty")
    owner_matches = mode not in (
        "counter-copy-foreign", "counter-owner-foreign",
        "counter-callable-foreign", "counter-callable-empty"
    )
    assert fields["counter.frequency_callback_type_matches"] == str(int(type_matches))
    assert fields["counter.frequency_callback_owner_matches"] == str(int(owner_matches))
    assert fields["counter.listener_count"] == "0"
    assert fields["counter.frequency_table_entries"] == "3"
    assert int(fields["counter.frequency_table_capacity_entries"]) <= 2008
    scheduled = mode == "counter-pending"
    assert fields["counter.next_frequency_entry"] == str(int(scheduled))
    assert fields["counter.frequency_event_scheduled"] == str(int(scheduled))
    events = [event for event in inventory["events"]
              if event["event_alias"] == fields["counter.frequency_event"]]
    assert len(events) == int(scheduled)
    if scheduled:
        assert fields["counter.frequency_event_tick"] == "0"
        assert events[0]["tick"] == "0"
    else:
        assert "counter.frequency_event_tick" not in fields
    return inventory


# Startup establishes the original CPU/member callbacks but the exclusive
# zero boundary services none. There is no drain, capture, or guest effect.
boundary = m5.simulateUntilBoundary(0, 1)
assert boundary.processedEvents == 0
before = m5.crucibleEventPosition()
counter_before = counter_inventory() if mode.startswith("counter-") else None
if mode == "counter-pending":
    # The diagnostic helper must refuse a queued member without copying links.
    assert not system.counter.crucibleDiagnosticFrequencyMutation(0, system.counter.getCCObject())
    assert counter_before == counter_inventory()
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
assert inspection[0] == (mode in (
    "owned", "foreign-helper", "unarmed", "counter-owned", "counter-pending",
    "counter-copy-original"
))
if counter_before is not None:
    # Neither a completed nor a refused source walk permits another callback
    # mutation through this diagnostic entry point.
    assert not system.counter.crucibleDiagnosticFrequencyMutation(0, system.counter.getCCObject())
    assert counter_before == counter_inventory()
    assert m5.crucibleEventPosition() == after
    # Both the original event member and raw cached state survive observation.
    # This is no source-cut, listener, backing-resource or restore certificate.
    print(json.dumps({
        "schema": "crucible.gem5.diagnostic-system-counter-source.v1",
        "mode": mode,
        "native_position": dict(after),
        "counter": counter_before,
        "source_cut_qualified": False,
        "listener_closure_qualified": False,
        "native_backing_qualified": False,
        "restore_qualified": False,
    }, sort_keys=True, separators=(",", ":")), flush=True)

if mode in ("foreign-helper", "counter-copy-original"):
    child = os.fork()
    if child == 0:
        # Invoke the actual public C++ helper directly, bypassing private
        # walk() so its intrinsic guard is the cause of this refusal.
        if mode == "foreign-helper":
            native_event.crucibleDiagnosticDirectQueueOwnership()
        else:
            system.counter.crucibleDiagnosticFrequencyMutation(0, system.counter.getCCObject())
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
