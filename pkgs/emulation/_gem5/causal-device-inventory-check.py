# SPDX-License-Identifier: MIT
"""Checks native descriptor traffic, sealed delivery time, and retained custody."""

import hashlib
import json
import struct

import m5
from m5.objects import (
    AddrRange,
    Root,
    SimpleMemory,
    SrcClockDomain,
    System,
    SystemXBar,
    VirtIONet,
    VirtIOQueueWitness,
    VoltageDomain,
)

system = System()
system.clk_domain = SrcClockDomain(clock="1GHz", voltage_domain=VoltageDomain())
system.mem_mode = "atomic"
system.mem_ranges = [AddrRange("128KiB")]
system.bus = SystemXBar()
system.memory = SimpleMemory(range=system.mem_ranges[0])
system.memory.port = system.bus.mem_side_ports
system.system_port = system.bus.cpu_side_ports
system.net = VirtIONet(queue_size=2, frame_capacity=2, maximum_frame_bytes=64)
system.witness = VirtIOQueueWitness()
root = Root(full_system=False, system=system)
m5.instantiate()
system.witness.prepareNetwork(system.net.getCCObject())
for _ in range(64):
    if list(system.net.pendingTxMetadata()):
        break
    m5.simulateUntilBoundary(1, 1)
else:
    raise AssertionError("actual native transmit callback never published")

packet = list(range(14))
original_tx = list(system.net.pendingTxMetadata())
assert len(original_tx) == 5 and original_tx[:3] == [1, 0, 17]
assert original_tx[3] > 0 and original_tx[4] > 0
assert list(system.net.pendingTxBytes()) == packet
assert not system.net.acknowledgeTx(2)
assert list(system.net.pendingTxBytes()) == packet

assert system.net.stageRx(1, 5, 23, packet)
assert system.net.stageRx(1, 5, 23, packet)
assert not system.net.stageRx(1, 5, 24, packet)
assert not system.net.stageRx(1, 5, 23, list(reversed(packet)))
assert not system.net.stageRx(3, 10, 24, packet)
assert not system.net.retireRx(1)
assert system.net.stageRx(2, 10, 24, packet)
assert not system.net.stageRx(3, 10, 24, packet)

# The excluded input tick remains unexecuted even when native inputs exist.
excluded = m5.simulateUntilBoundary(5, 100)
assert excluded.processedEvents == 0
assert excluded.nextTick == 5
assert list(system.net.pendingRxMetadata()) == [1, 5, 23, 0, 2, 10, 24, 0]

delivered = m5.simulateUntilBoundary(6, 1)
assert delivered.processedEvents == 1
assert delivered.currentTick == 5
delivery = list(system.net.pendingRxCompletionMetadata())
assert len(delivery) == 7
assert delivery[:2] == [1, 5] and delivery[2] > original_tx[3]
assert delivery[3] > 0 and delivery[4:] == [17, 23, 14]
assert list(system.net.pendingRxMetadata()) == [1, 5, 23, 1, 2, 10, 24, 0]
assert bytes(system.physProxy.read(0x9000, 26)) == bytes(10) + b"\x01\x00" + bytes(packet)
used = bytes(system.physProxy.read(0x7000, 12))
assert struct.unpack_from("<H", used, 2)[0] == 1
assert struct.unpack_from("<II", used, 4) == (0, 26)
assert list(system.net.pendingTxMetadata()) == original_tx
assert list(system.net.pendingTxBytes()) == packet

# Diagnostics read actual retained storage without consuming the next event.
before_inventory = m5.simulateUntilBoundary(6, 0)
inventory = m5.crucibleStateInventory()
assert inventory == m5.crucibleStateInventory()
assert inventory["complete"] is False
native = next(item for item in inventory["objects"] if item["name"] == "system.net")
assert native["state_complete"] is False
fields = native["modeled_fields"]
assert fields["coverage.unsupported"]
assert fields["virtio.queue_count"] == "2"
assert fields["net.inputs.count"] == "2"
assert fields["net.outputs.count"] == "1"
assert fields["net.outputs[0].event_ordinal"] == str(original_tx[3])
assert fields["net.outputs[0].tick_ordinal"] == str(original_tx[4])
assert fields["net.outputs[0].payload.bytes"] == "14"
assert fields["net.outputs[0].payload.sha256"] == hashlib.sha256(bytes(packet)).hexdigest()
assert fields["net.inputs[0].consumed"] == "1"
assert fields["net.inputs[0].consumed_tick"] == "5"
assert fields["net.inputs[0].event_ordinal"] == str(delivery[2])
assert fields["net.inputs[1].consumed"] == "0"
after_inventory = m5.simulateUntilBoundary(6, 0)
assert after_inventory.currentTick == before_inventory.currentTick
assert after_inventory.nextTick == before_inventory.nextTick
assert after_inventory.processedEvents == 0


# The explicitly selected scope retains original queue/device fields and RNG,
# while CPU/RAM/unselected bodies remain omitted diagnostic coverage.
partial = m5.crucibleDeviceStateInventory([system.net.path()])
assert partial == m5.crucibleDeviceStateInventory([system.net.path()])
assert partial["schema"] == "crucible.gem5.causal-device-state.v1"
assert partial["complete"] is False
assert partial["diagnostic_scope"] == "native-events-rng-selected-device-fields-v1"
assert partial["selected_names"] == ["system.net"]
assert [item["name"] for item in partial["objects"]] == ["system.net"]
selected = partial["objects"][0]["modeled_fields"]
for key in ["virtio.queue_count", "net.inputs.count", "net.outputs.count",
            "net.outputs[0].event_ordinal", "net.outputs[0].tick_ordinal",
            "net.outputs[0].payload.bytes", "net.outputs[0].payload.sha256",
            "net.inputs[0].consumed", "net.inputs[0].consumed_tick"]:
    assert selected[key] == fields[key]
assert partial["rng"] == inventory["rng"]
assert all(item["payload_complete"] is False for item in partial["events"])
assert "cpu-pipeline-and-registers" in partial["unsupported_domains"]
assert list(system.net.crucibleTxPublicationInventory()) == [original_tx]
assert list(system.net.crucibleTxPublicationBytes(original_tx[0])) == packet
for rejected in [[], ["missing"], ["system.net", "system.net"], ["system.net"] * 17]:
    try:
        m5.crucibleDeviceStateInventory(rejected)
    except (ValueError, RuntimeError):
        pass
    else:
        raise AssertionError("invalid device diagnostic scope was admitted")
try:
    system.net.crucibleTxPublicationBytes(99)
except (ValueError, RuntimeError):
    pass
else:
    raise AssertionError("unknown retained publication identity was admitted")
assert list(system.net.crucibleTxPublicationInventory()) == [original_tx]
assert partial == m5.crucibleDeviceStateInventory([system.net.path()])
assert m5.simulateUntilBoundary(6, 0).processedEvents == 0

assert not system.net.retireRx(2)
assert system.net.retireRx(1)
assert system.net.retireRx(1)
assert not system.net.stageRx(1, 5, 23, packet)
assert list(system.net.pendingRxMetadata()) == [2, 10, 24, 0]
assert system.net.acknowledgeTx(1)
assert system.net.acknowledgeTx(1)
assert list(system.net.pendingTxMetadata()) == []

# Publication frees TX credit through a native event. The future RX event
# remains excluded, and its original input stays retained for guest buffers.
after_ack = m5.simulateUntilBoundary(10, 100)
assert after_ack.currentTick == 5
assert after_ack.nextTick == 10
assert list(system.net.pendingRxMetadata()) == [2, 10, 24, 0]

print(
    json.dumps(
        {
            "schema": "crucible.gem5.virtio-network-mechanism.v1",
            "actualRxBytes": 14,
            "actualTxBytes": 14,
            "sealedTick": 5,
            "retainedFutureTick": 10,
            "guestBootVerified": False,
            "deviceParityQualified": False,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
)

print(json.dumps({"schema":"crucible.gem5.causal-device-diagnostic-mechanism.v1",
    "readOnlyRepeatedObservation": True,"selectedDeviceFieldsVerified": True,
    "originalFifoBytesVerified": True,"unknownIdentityRefused": True,
    "emptyMissingDuplicateOversizeScopeRefused": True,
    "typedDiagnosticComplete": False,"opaqueCaptureQualified": False,
},sort_keys=True,separators=(",", ":")))
