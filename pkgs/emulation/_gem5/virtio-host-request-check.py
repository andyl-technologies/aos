# SPDX-License-Identifier: MIT
"""Checks actual asynchronous block/9p DMA against sealed reply timing."""
import hashlib
import json
import struct
import sys

import m5
from m5.objects import (
    AddrRange, Root, SimpleMemory, SrcClockDomain, System, SystemXBar,
    VirtIOHostRequest, VirtIOQueueWitness, VoltageDomain,
)

if len(sys.argv) not in (2, 3) or sys.argv[1] not in ("block", "9p"):
    raise RuntimeError("expected block or 9p native request probe")

kind = sys.argv[1]
reprogram = len(sys.argv) == 3 and sys.argv[2] == "reprogram"
system = System()
system.clk_domain = SrcClockDomain(clock="1GHz", voltage_domain=VoltageDomain())
system.mem_mode = "atomic"
system.mem_ranges = [AddrRange("128KiB")]
system.bus = SystemXBar()
system.memory = SimpleMemory(range=system.mem_ranges[0])
system.memory.port = system.bus.mem_side_ports
system.system_port = system.bus.cpu_side_ports
system.device = VirtIOHostRequest(
    kind=kind, queue_size=2, request_capacity=1,
    maximum_payload_bytes=512, capacity_sectors=1024,
)
system.witness = VirtIOQueueWitness()
root = Root(full_system=False, system=system)
m5.instantiate()
system.witness.prepareHostRequest(system.device.getCCObject(), kind)
for _ in range(64):
    if list(system.device.pendingRequestMetadata()):
        break
    m5.simulateUntilBoundary(1, 1)
else:
    raise AssertionError("actual native request callback never published")

metadata = [1, 0, 17, 0, 0, 0, 512] if kind == "block" else [1, 0, 17, 100, 0, 65535, 64]
actual = list(system.device.pendingRequestMetadata())
assert len(actual) == 9 and actual[:7] == metadata
assert actual[7] > 0 and actual[8] > 0
assert not system.device.retireCompleted(1)
if kind == "block":
    assert list(system.device.pendingRequestBytes()) == []
    reply = [byte % 256 for byte in range(512)]
    assert not system.device.stageReply(1, 5, 23, 0, reply[:-1])
else:
    original = list(system.device.pendingRequestBytes())
    assert len(original) == 21 and original[4] == 100
    reply = original[:]
    reply[4] = 101
    invalid = reply[:]
    invalid[5] = 0
    assert not system.device.stageReply(1, 5, 23, 0, invalid)

assert not system.device.stageReply(2, 5, 23, 0, reply)
assert system.device.stageReply(1, 5, 23, 0, reply)
assert system.device.stageReply(1, 5, 23, 0, reply)
assert not system.device.stageReply(1, 5, 24, 0, reply)

# A guest descriptor change after request birth cannot redirect reply custody.
system.physProxy.write(0x1010, struct.pack("<Q", 0xc000))
assert bytes(system.physProxy.read(0xb000, len(reply))) == bytes(len(reply))
assert not system.device.acknowledgeRequest(2)
assert system.device.acknowledgeRequest(1)
assert list(system.device.pendingRequestMetadata()) == []
assert not system.device.retireCompleted(1)

sealed = m5.simulateUntilBoundary(5, 100)
assert sealed.hasNextEvent and sealed.nextTick == 5
assert sealed.processedEvents == 0
assert bytes(system.physProxy.read(0xb000, len(reply))) == bytes(len(reply))
if reprogram:
    system.witness.reprogramHostQueue(system.device.getCCObject())
completed = m5.simulateUntilBoundary(6, 1)
if reprogram:
    raise AssertionError("reconfigured native queue accepted an original reply")
assert completed.currentTick == 5
receipt = list(system.device.pendingCompletionMetadata())
assert len(receipt) == 9 and receipt[:2] == [1, 5]
assert receipt[2] > actual[7] and receipt[3] > 0
assert receipt[4:8] == [0, len(reply) + (kind == "block"), 17, 23]
assert receipt[8] > 0
assert bytes(system.physProxy.read(0xb000, len(reply))) == bytes(reply)
assert bytes(system.physProxy.read(0xc000, len(reply))) == bytes(len(reply))
used = bytes(system.physProxy.read(0x7000, 12))
assert struct.unpack_from("<H", used, 2)[0] == 1
assert struct.unpack_from("<II", used, 4) == (0, len(reply) + (kind == "block"))
# Original request, frozen spans and completed reply remain diagnostic data.
before_inventory = m5.simulateUntilBoundary(6, 0)
inventory = m5.crucibleStateInventory()
assert inventory == m5.crucibleStateInventory()
assert inventory["complete"] is False
native = next(item for item in inventory["objects"] if item["name"] == "system.device")
assert native["state_complete"] is False
fields = native["modeled_fields"]
assert fields["coverage.unsupported"]
assert fields["request.retained_count"] == "1"
assert fields["request.retained[0].birth_ordinal"] == str(actual[7])
assert fields["request.retained[0].completion_ordinal"] == str(receipt[2])
assert fields["request.retained[0].queue_incarnation"] == str(receipt[8])
assert fields["request.retained[0].span[0].address"] == str(0xb000)
assert fields["request.retained[0].reply.sha256"] == hashlib.sha256(bytes(reply)).hexdigest()
assert fields["request.retained[0].acknowledged"] == "1"
assert fields["request.retained[0].completed"] == "1"
after_inventory = m5.simulateUntilBoundary(6, 0)
assert after_inventory.currentTick == before_inventory.currentTick
assert after_inventory.hasNextEvent == before_inventory.hasNextEvent
assert after_inventory.processedEvents == 0

assert system.device.retireCompleted(1)
assert system.device.retireCompleted(1)
assert not system.device.stageReply(1, 5, 23, 0, reply)

print(json.dumps({
    "schema": "crucible.gem5.virtio-host-request-mechanism.v1",
    "kind": kind, "replyBytes": len(reply), "sealedTick": 5,
    "frozenGuestSpansVerified": True,
    "guestBootVerified": False, "deviceParityQualified": False,
}, sort_keys=True, separators=(",", ":")))
