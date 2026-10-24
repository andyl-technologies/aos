# SPDX-License-Identifier: MIT
"""Exercises the actual counter producer while its cached value is stale.

Only two finite no-op events and one real frequency callback can execute. This
counter-only mechanism does not select a source scope or qualify a native cut.
"""

import json

import m5
import m5.event
from m5.objects import (
    AddrRange,
    Root,
    SimpleMemory,
    SrcClockDomain,
    System,
    SystemCounter,
    SystemXBar,
    VoltageDomain,
)


class StoppedMarker(m5.event.Event):
    """Records one actual finite event birth without reading the counter."""

    def __init__(self):
        super().__init__()
        self.births = []

    def __call__(self):
        self.births.append(dict(m5.crucibleEventPosition()))


m5.ticks.setGlobalFrequency("1THz")
m5.core.disableAllListeners()
system = System(mem_mode="atomic")
system.clk_domain = SrcClockDomain(clock="1GHz", voltage_domain=VoltageDomain())
system.mem_ranges = [AddrRange("128KiB")]
system.bus = SystemXBar()
system.memory = SimpleMemory(range=system.mem_ranges[0])
system.memory.port = system.bus.mem_side_ports
system.system_port = system.bus.cpu_side_ports
system.counter = SystemCounter(freqs=[1000000000, 500000000])
root = Root(full_system=False, system=system)
m5.instantiate()

first = StoppedMarker()
later = StoppedMarker()
queue = m5.event.getEventQueue(0)
queue.schedule(first, 2001)
queue.schedule(later, 3001)
step = m5.simulateUntilBoundary(2002, 100)
assert step.currentTick == 2001 and len(first.births) == 1 and not later.births
assert later.scheduled() and later.when() == 3001
position = dict(m5.crucibleEventPosition())
assert position["tick"] == "2001" and not position["active"]


def observe():
    """Reads the existing selected-object observer and checks unchanged time."""
    result = m5.crucibleDeviceStateInventory(["system.counter"])
    assert result["complete"] is False and len(result["objects"]) == 1
    assert result["objects"][0]["state_complete"] is False
    assert m5.crucibleEventPosition() == position
    assert later.scheduled() and later.when() == 3001 and not later.births
    return result


stale = observe()
assert observe() == stale
fields = stale["objects"][0]["modeled_fields"]
# At 2001 ps value() would normalize these fields to 2 and 2000. The producer
# must preserve the actual stored zero values instead of presenting that view.
assert fields["counter.cached_value"] == "0"
assert fields["counter.update_tick"] == "0"
assert fields["counter.frequency"] == "1000000000"
assert fields["counter.period"] == "1000"

# This real mutating hardware API intentionally updates the cache and queues
# its original member callback at the current tick, which remains unserviced.
system.counter.freqUpdateSchedule(1)
pending = observe()
assert observe() == pending
fields = pending["objects"][0]["modeled_fields"]
assert fields["counter.cached_value"] == "2"
assert fields["counter.update_tick"] == "2000"
assert fields["counter.next_frequency_entry"] == "1"
assert fields["counter.frequency_event_scheduled"] == "1"
assert fields["counter.frequency_event_tick"] == "2001"
event = [event for event in pending["events"]
         if event["event_alias"] == fields["counter.frequency_event"]]
assert len(event) == 1 and event[0]["tick"] == "2001"

step = m5.simulateUntilBoundary(2002, 1)
assert step.processedEvents == 1 and step.currentTick == 2001
position = dict(m5.crucibleEventPosition())
assert position["tick"] == "2001" and not position["active"]
changed = observe()
assert observe() == changed
fields = changed["objects"][0]["modeled_fields"]
assert fields["counter.cached_value"] == "2"
assert fields["counter.update_tick"] == "2000"
assert fields["counter.frequency"] == "500000000"
assert fields["counter.increment"] == "2"
assert fields["counter.period"] == "2000"
assert fields["counter.frequency_event_scheduled"] == "0"
assert "counter.frequency_event_tick" not in fields

print(json.dumps({
    "schema": "crucible.gem5.system-counter-observation-mechanism.v1",
    "stale": stale,
    "pending": pending,
    "changed": changed,
    "final_position": position,
    "later_tick": str(later.when()),
    "source_cut_qualified": False,
    "listener_closure_qualified": False,
    "native_backing_qualified": False,
    "restore_qualified": False,
    "linux_qualified": False,
    "common_ready_qualified": False,
}, sort_keys=True, separators=(",", ":")), flush=True)
