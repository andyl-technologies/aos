# SPDX-License-Identifier: MIT
"""Checks native event boundaries and process images, not CPU/device coverage."""

import ctypes
import hashlib
import json
from pathlib import Path
import random
import sys

import m5
from m5.event import Event
from m5.objects import Root
from _m5.event import getEventQueue


mode, prefix = sys.argv[1:]
m5.core.disableAllListeners()
root = Root(full_system=False)
m5.instantiate()
try:
    m5.crucibleStateInventory()
except RuntimeError:
    pass
else:
    raise AssertionError("inspection performed model startup")
queue = getEventQueue(0)
generator = random.Random(173953)
memory = [generator.getrandbits(64) for _ in range(128)]
trace = []


class PendingEvent(Event):
    def __init__(self, identifier):
        super().__init__(priority=0)
        self.identifier = identifier

    def __call__(self):
        try:
            m5.crucibleStateInventory()
        except RuntimeError:
            pass
        else:
            raise AssertionError("inspection entered an executing model")
        value = generator.getrandbits(64)
        memory[self.identifier] ^= value
        trace.append((m5.curTick(), self.identifier, value, memory[self.identifier]))


events = [PendingEvent(index) for index in range(16)]
for index, event in enumerate(events):
    queue.schedule(event, 10 + index // 4)

m5.simulateUntilBoundary(0, 0)
initial_inventory = m5.crucibleStateInventory()
assert initial_inventory == m5.crucibleStateInventory()
assert initial_inventory["complete"] is False
assert initial_inventory["unsupported_domains"]
assert initial_inventory["native_tick"] == "0"
identities = [item["event_identity"] for item in initial_inventory["events"]]
assert len(identities) == 16 and len(set(identities)) == 16


def state_fingerprint():
    """Reads all future-affecting state owned by this small fixture."""
    boundary = m5.simulateUntilBoundary(100, 0)
    value = {
        "rng": generator.getstate(),
        "memory": memory,
        "trace": trace,
        "events": [(event.identifier, event.scheduled()) for event in events],
        "boundary": [
            boundary.currentTick,
            boundary.hasNextEvent,
            boundary.nextTick,
            boundary.nextPriority,
        ],
        "native_inventory": m5.crucibleStateInventory(),
    }
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


status = 1
if mode in ("bounded", "capture"):
    before_first = m5.simulateUntilBoundary(10, 100)
    assert before_first.processedEvents == 0
    assert before_first.currentTick == 0
    assert before_first.nextTick == 10

    cut = m5.simulateUntilBoundary(100, 1)
    assert cut.processedEvents == 1
    assert cut.currentTick == 10
    assert cut.hasNextEvent and cut.nextTick == 10
    assert len(trace) == 1 and trace[0][1] == 3
    assert sum(event.scheduled() for event in events) == 15
    assert [item["event_identity"] for item in m5.crucibleStateInventory()["events"]] == identities[1:]
    before = state_fingerprint()

    if mode == "capture":
        library = ctypes.CDLL(None)
        assert library.dmtcp_get_ckpt_signal() == 40
        checkpoint = library.dmtcp_checkpoint
        checkpoint.argtypes = []
        checkpoint.restype = ctypes.c_int
        status = checkpoint()
        if status not in (1, 2):
            raise RuntimeError(f"DMTCP checkpoint failed: {status}")

    assert state_fingerprint() == before
elif mode != "baseline":
    raise ValueError(f"unknown fixture mode: {mode}")

result = m5.simulateUntilBoundary(100, 100)
assert result.exitEvent is None
assert not result.hasNextEvent
assert len(trace) == 16
assert [item[1] for item in trace] == [
    index for group in range(4) for index in range(group * 4 + 3, group * 4 - 1, -1)
]

# An idle grant leaves the native tick unchanged. Logical time mapping belongs
# to the owner adapter and must not be inferred from a synthetic exit event.
final_tick = m5.curTick()
idle = m5.simulateUntilBoundary(1000, 100)
assert idle.processedEvents == 0 and idle.currentTick == final_tick

suffix = "restored" if status == 2 else "original"
Path(f"{prefix}.{suffix}").write_text(json.dumps(trace) + "\n")
