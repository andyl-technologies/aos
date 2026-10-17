# SPDX-License-Identifier: MIT
"""Exercises actual publication stops, owned PyEvents, ceilings and real status.

This is a native queue primitive witness, not Linux/capture/admission evidence.
"""

import json
import sys

import m5
import m5.event
from m5.objects import (
    AddrRange, Root, SimpleMemory, SrcClockDomain, System, SystemXBar,
    VirtIOHostRequest, VirtIOQueueWitness, VoltageDomain,
)


if len(sys.argv) != 2 or sys.argv[1] not in ('enabled', 'disabled'):
    raise ValueError('expected exact source-selected publication-stop mode')
enabled = sys.argv[1] == 'enabled'
system = System()
system.clk_domain = SrcClockDomain(clock='1GHz', voltage_domain=VoltageDomain())
system.mem_mode = 'atomic'
system.mem_ranges = [AddrRange('128KiB')]
system.bus = SystemXBar()
system.memory = SimpleMemory(range=system.mem_ranges[0])
system.memory.port = system.bus.mem_side_ports
system.system_port = system.bus.cpu_side_ports
system.device = VirtIOHostRequest(
    kind='block', queue_size=2, request_capacity=1,
    maximum_payload_bytes=512, capacity_sectors=1024,
)
system.witness = VirtIOQueueWitness()
root = Root(full_system=False, system=system)
m5.instantiate()
assert m5.crucibleDeviceBoundaryState() == {'enabled': False, 'publication_epoch': '0'}
if enabled:
    assert m5.crucibleConfigureDeviceBoundaries()
    assert not m5.crucibleConfigureDeviceBoundaries()


class BackendReaction(m5.event.Event):
    def __init__(self, owner):
        super().__init__()
        self.owner = owner

    def __call__(self):
        position = m5.crucibleEventPosition()
        assert position['active'] and position['tick'] == '5'
        self.owner.reactions.append(dict(position))
        # Error status 2 deliberately differs from actual descriptor head 0.
        assert system.device.stageReply(1, 6, 23, 2, [])


class BirthHandler(m5.event.Event):
    def __init__(self):
        super().__init__()
        self.originals = []
        self.reactions = []
        self.future = BackendReaction(self)

    def __call__(self):
        position = m5.crucibleEventPosition()
        assert position['active'] and position['tick'] == '0'
        metadata = list(system.device.pendingRequestMetadata())
        assert metadata[:7] == [1, 0, 17, 0, 0, 0, 512]
        assert metadata[7:] == [int(position['ordinal']), int(position['tick_ordinal'])]
        self.originals.append((metadata, bytes(system.device.pendingRequestBytes())))
        m5.event.getEventQueue(0).schedule(self.future, 5)


handler = BirthHandler()
assert not system.device.bindRequestHandler(None)
assert system.device.bindRequestHandler(handler)
assert not system.device.bindRequestHandler(handler)
system.witness.prepareHostRequest(system.device.getCCObject(), 'block')
zero = m5.simulateUntilBoundary(0, 100)
assert zero.processedEvents == 0 and not handler.originals and not handler.reactions
first = m5.simulateUntilBoundary(7, 100)
assert len(handler.originals) == 1
assert not system.device.bindRequestHandler(handler)
if enabled:
    assert first.currentTick == 0 and first.nextTick == 5
    assert not handler.reactions
    epoch = m5.crucibleDeviceBoundaryState()
    assert epoch == {'enabled': True, 'publication_epoch': '1'}
    assert m5.simulateUntilBoundary(5, 100).processedEvents == 0
    assert not handler.reactions
    reaction = m5.simulateUntilBoundary(6, 100)
    assert reaction.currentTick == 5 and reaction.nextTick == 6
    assert len(handler.reactions) == 1
    assert list(system.device.crucibleCompletionInventory()) == []
    completed = m5.simulateUntilBoundary(7, 100)
    assert completed.currentTick == 6
else:
    assert first.currentTick == 6 and len(handler.reactions) == 1
    assert m5.crucibleDeviceBoundaryState() == {'enabled': False, 'publication_epoch': '0'}
    assert not m5.crucibleConfigureDeviceBoundaries()

completion = [list(row) for row in system.device.crucibleCompletionInventory()]
assert len(completion) == 1
row = completion[0]
assert len(row) == 10 and row[0:2] == [1, 6]
assert row[2] > int(handler.reactions[0]['ordinal']) and row[3] > 0
assert row[4:] == [2, 513, 17, 23, 1, 0]
assert list(system.device.pendingCompletionMetadata())[4] == row[9] == 0
assert row[4] != row[9]
assert bytes(system.physProxy.read(0xb000, 512)) == bytes(512)
assert bytes(system.physProxy.read(0xb200, 1)) == bytes([2])
assert completion == [list(value) for value in system.device.crucibleCompletionInventory()]
assert system.device.acknowledgeRequest(1)
assert system.device.retireCompleted(1)
assert system.device.retireCompleted(1)
print(json.dumps({
    'schema': 'crucible.gem5.closed-block-native-boundary-mechanism.v1',
    'mode': sys.argv[1], 'actual_request_birth_handler': True,
    'native_owned_future_py_event': True, 'exclusive_ceiling_preserved': True,
    'real_status_separate_from_descriptor_head': True,
    'disabled_profile_semantics_preserved': not enabled,
    'linux_ready_qualified': False, 'opaque_capture_qualified': False,
    'common_admission_qualified': False, 'device_parity_qualified': False,
}, sort_keys=True, separators=(',', ':')))
