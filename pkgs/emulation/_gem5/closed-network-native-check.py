# SPDX-License-Identifier: MIT
"""Exercises actual TX birth, owned future RX and unchanged disabled stops.

The actual native RAM/queue witness grants no Linux or checkpoint admission.
"""

import json
import sys

import m5
import m5.event
from m5.objects import (
    AddrRange, Root, SimpleMemory, SrcClockDomain, System, SystemXBar,
    VirtIONet, VirtIOQueueWitness, VoltageDomain,
)


if len(sys.argv) != 2 or sys.argv[1] not in ('enabled', 'disabled'):
    raise ValueError('expected exact source-selected device-stop mode')
enabled = sys.argv[1] == 'enabled'
system = System()
system.clk_domain = SrcClockDomain(clock='1GHz', voltage_domain=VoltageDomain())
system.mem_mode = 'atomic'
system.mem_ranges = [AddrRange('128KiB')]
system.bus = SystemXBar()
system.memory = SimpleMemory(range=system.mem_ranges[0])
system.memory.port = system.bus.mem_side_ports
system.system_port = system.bus.cpu_side_ports
system.net = VirtIONet(queue_size=2, frame_capacity=2, maximum_frame_bytes=64)
system.witness = VirtIOQueueWitness()
root = Root(full_system=False, system=system)
m5.instantiate()
assert m5.crucibleDeviceBoundaryState() == {'enabled': False, 'publication_epoch': '0'}
if enabled:
    assert m5.crucibleConfigureDeviceBoundaries()
    assert not m5.crucibleConfigureDeviceBoundaries()


class ReceiveReaction(m5.event.Event):
    def __init__(self, owner):
        super().__init__()
        self.owner = owner

    def __call__(self):
        point = m5.crucibleEventPosition()
        assert point['active'] and point['tick'] == '5'
        self.owner.reactions.append(dict(point))
        assert system.net.stageRx(1, 6, 23, list(self.owner.originals[0][1]))


class TransmitHandler(m5.event.Event):
    def __init__(self):
        super().__init__()
        self.originals = []
        self.reactions = []
        self.future = ReceiveReaction(self)

    def __call__(self):
        point = m5.crucibleEventPosition()
        assert point['active'] and point['tick'] == '0'
        records = [list(row) for row in system.net.crucibleTxPublicationInventory()]
        assert len(records) == 1
        assert records[0] == [1, 0, 17, int(point['ordinal']), int(point['tick_ordinal'])]
        self.originals.append((records[0], bytes(system.net.crucibleTxPublicationBytes(1))))
        m5.event.getEventQueue(0).schedule(self.future, 5)


handler = TransmitHandler()
assert not system.net.bindTransmitHandler(None)
assert system.net.bindTransmitHandler(handler)
assert not system.net.bindTransmitHandler(handler)
system.witness.prepareNetwork(system.net.getCCObject())
assert m5.simulateUntilBoundary(0, 100).processedEvents == 0
assert not handler.originals
first = m5.simulateUntilBoundary(7, 100)
assert handler.originals[0][1] == bytes(range(14))
assert not system.net.bindTransmitHandler(handler)
if enabled:
    assert first.currentTick == 0 and first.nextTick == 5
    assert not handler.reactions
    assert m5.crucibleDeviceBoundaryState() == {'enabled': True, 'publication_epoch': '1'}
    assert m5.simulateUntilBoundary(5, 100).processedEvents == 0
    reaction = m5.simulateUntilBoundary(6, 100)
    assert reaction.currentTick == 5 and reaction.nextTick == 6
    assert list(system.net.pendingRxMetadata()) == [1, 6, 23, 0]
    assert list(system.net.pendingRxCompletionMetadata()) == []
    delivered = m5.simulateUntilBoundary(7, 100)
    assert delivered.currentTick == 6
    assert m5.crucibleDeviceBoundaryState() == {'enabled': True, 'publication_epoch': '2'}
else:
    assert first.currentTick == 6 and len(handler.reactions) == 1
    assert m5.crucibleDeviceBoundaryState() == {'enabled': False, 'publication_epoch': '0'}
    assert not m5.crucibleConfigureDeviceBoundaries()

completion = list(system.net.pendingRxCompletionMetadata())
assert completion[:2] == [1, 6]
assert completion[2] > int(handler.reactions[0]['ordinal']) and completion[3] > 0
assert completion[4:] == [17, 23, 14]
assert list(system.net.pendingRxMetadata()) == [1, 6, 23, 1]
assert bytes(system.physProxy.read(0x9000, 26)) == bytes(10) + b'\x01\x00' + bytes(range(14))
assert bytes(system.net.crucibleTxPublicationBytes(1)) == bytes(range(14))
assert not system.net.acknowledgeTx(2)
assert not system.net.retireRx(2)
assert system.net.acknowledgeTx(1) and system.net.acknowledgeTx(1)
assert system.net.retireRx(1) and system.net.retireRx(1)
assert list(system.net.pendingRxMetadata()) == []
assert list(system.net.crucibleTxPublicationInventory()) == []
print(json.dumps({
    'schema': 'crucible.gem5.closed-network-native-boundary-mechanism.v1',
    'mode': sys.argv[1], 'actual_transmit_birth_handler': True,
    'native_owned_future_rx_py_event': True, 'exclusive_ceiling_preserved': True,
    'actual_guest_rx_bytes_verified': True, 'original_tx_ack_rx_retirement': True,
    'disabled_profile_semantics_preserved': not enabled,
    'linux_ready_qualified': False, 'opaque_capture_qualified': False,
    'common_admission_qualified': False, 'device_parity_qualified': False,
}, sort_keys=True, separators=(',', ':')))
