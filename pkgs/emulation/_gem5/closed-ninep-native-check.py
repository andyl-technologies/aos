# SPDX-License-Identifier: MIT
"""Checks actual 9p birth/reply FIFO and descriptor head distinct from status.

This native RAM primitive supplies no Linux, checkpoint or common admission.
"""

import json
import struct
import sys

import m5
import m5.event
from m5.objects import (
    AddrRange, Root, SimpleMemory, SrcClockDomain, System, SystemXBar,
    VirtIOHostRequest, VirtIOQueueWitness, VoltageDomain,
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
system.device = VirtIOHostRequest(kind='9p', queue_size=2, request_capacity=1,
                                  maximum_payload_bytes=512, capacity_sectors=1024)
system.witness = VirtIOQueueWitness()
root = Root(full_system=False, system=system)
m5.instantiate()
if enabled:
    assert m5.crucibleConfigureDeviceBoundaries()


class ReplyReaction(m5.event.Event):
    def __init__(self, owner):
        super().__init__()
        self.owner = owner

    def __call__(self):
        position = m5.crucibleEventPosition()
        assert position['active'] and position['tick'] == '5'
        self.owner.reactions.append(dict(position))
        original = self.owner.originals[0][1]
        reply = original[:4] + bytes([101]) + original[5:]
        assert system.device.stageReply(1, 6, 23, 0, list(reply))
        self.owner.reply = reply


class RequestHandler(m5.event.Event):
    def __init__(self):
        super().__init__()
        self.originals = []
        self.reactions = []
        self.reply = None
        self.future = ReplyReaction(self)

    def __call__(self):
        point = m5.crucibleEventPosition()
        assert point['active'] and point['tick'] == '0'
        rows = [list(row) for row in system.device.crucibleRequestPublicationInventory()]
        assert rows == [[1, 0, 17, 100, 0, 65535, 64,
                         int(point['ordinal']), int(point['tick_ordinal'])]]
        self.originals.append((rows[0], bytes(system.device.crucibleRequestPublicationBytes(1))))
        m5.event.getEventQueue(0).schedule(self.future, 5)


handler = RequestHandler()
assert system.device.bindRequestHandler(handler)
assert not system.device.bindRequestHandler(handler)
system.witness.prepareHostRequest(system.device.getCCObject(), '9p')
# Select head1 with its readable input chained to writable descriptor0. This
# legitimate guest geometry makes an accidental head-as-status codec fail.
input_descriptor = bytes(system.physProxy.read(0x1000, 16))
output_descriptor = bytes(system.physProxy.read(0x1010, 16))
system.physProxy.write(0x1000, output_descriptor)
system.physProxy.write(0x1010, input_descriptor[:14] + struct.pack('<H', 0))
system.physProxy.write(0x3004, struct.pack('<H', 1))
assert m5.simulateUntilBoundary(0, 100).processedEvents == 0
first = m5.simulateUntilBoundary(7, 100)
assert len(handler.originals) == 1
original = handler.originals[0][1]
assert len(original) == 21 and struct.unpack_from('<IBH', original) == (21, 100, 65535)
if enabled:
    assert first.currentTick == 0 and first.nextTick == 5
    assert not handler.reactions
    assert m5.crucibleDeviceBoundaryState()['publication_epoch'] == '1'
    assert m5.simulateUntilBoundary(5, 100).processedEvents == 0
    reaction = m5.simulateUntilBoundary(6, 100)
    assert reaction.currentTick == 5 and reaction.nextTick == 6
    assert bytes(system.physProxy.read(0xb000, 21)) == bytes(21)
    completed = m5.simulateUntilBoundary(7, 100)
    assert completed.currentTick == 6
    assert m5.crucibleDeviceBoundaryState()['publication_epoch'] == '2'
else:
    assert first.currentTick == 6 and len(handler.reactions) == 1
    assert m5.crucibleDeviceBoundaryState() == {'enabled': False, 'publication_epoch': '0'}

rows = [list(row) for row in system.device.crucibleCompletionInventory()]
assert len(rows) == 1
completion = rows[0]
assert completion[0:2] == [1, 6]
assert completion[2] > int(handler.reactions[0]['ordinal']) and completion[3] > 0
assert completion[4:8] == [0, 21, 17, 23]
assert completion[8] > 0 and completion[9] == 1
assert bytes(system.physProxy.read(0xb000, 21)) == handler.reply
assert struct.unpack_from('<II', bytes(system.physProxy.read(0x7000, 12)), 4) == (1, 21)
assert not system.device.acknowledgeRequest(2)
assert system.device.acknowledgeRequest(1) and system.device.acknowledgeRequest(1)
assert not system.device.retireCompleted(2)
assert system.device.retireCompleted(1) and system.device.retireCompleted(1)
assert [list(row) for row in system.device.crucibleCompletionInventory()] == []
print(json.dumps({
    'schema': 'crucible.gem5.closed-ninep-native-boundary-mechanism.v1',
    'mode': sys.argv[1], 'actual_request_birth_handler': True,
    'strong_owned_future_reply_event': True, 'exclusive_ceiling_preserved': True,
    'original_9p_tag_reply_bytes_verified': True, 'head1_status0_independently_verified': True,
    'completion_excludes_block_status_octet': True,
    'original_request_ack_completion_retirement': True,
    'linux_ready_qualified': False, 'opaque_capture_qualified': False,
    'common_admission_qualified': False, 'device_parity_qualified': False,
}, sort_keys=True, separators=(',', ':')))
